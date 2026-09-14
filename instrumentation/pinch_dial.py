"""Relative motion and a virtual dial driven by recognized band gestures.

Gyro scaling is an experimental interpretation of the observed 0.07 config
value. This is a relative illustration, not calibrated hand pose estimation.
Gesture and gyro device timestamps use different epochs: only gyro timestamps
are integrated; receive time controls freshness and gesture ordering.
"""

import math
import time
from collections import deque


def multiply(a, b):
    w, x, y, z = a
    v, i, j, k = b
    return [w*v-x*i-y*j-z*k, w*i+x*v+y*k-z*j,
            w*j-x*k+y*v+z*i, w*k+x*j-y*i+z*v]


class PinchDial:
    def __init__(self, emit, clock=time.monotonic):
        self.emit, self.clock = emit, clock
        self.value = 50
        self.hand = self.hand_error = None
        self.active = False
        self.fingers = {"index": False, "middle": False}
        self.pressed_at = {}
        self.last_gyro_at = self.last_device_time = None
        self.last_publish = -math.inf
        self.bias = [0., 0., 0.]
        self.rotation = [1., 0., 0., 0.]
        self.integral = [0., 0., 0.]
        self.axis = None
        self.remainder = 0.
        self.gestures = self.steps = 0
        self.last_gesture = None
        self.recent_gestures = deque(maxlen=32)
        self.reason = "Waiting for motion"
        self.gyro_scale = .07
        self.response = "direct"
        self.sensitivity = 1.

    def set_hand(self, hand, error=None):
        if hand not in (None, "left", "right"):
            raise ValueError("Hand must be left or right")
        self.hand, self.hand_error = hand, error
        self.fingers = dict.fromkeys(self.fingers, False)
        self.pressed_at.clear()
        self.release(error or ("Hand confirmed · pinch to turn the dial" if hand else "Waiting for band hand setting"))
        self.publish(True)

    def configure(self, response="direct", sensitivity=1.):
        if response not in ("direct", "rate") or not isinstance(sensitivity, (int, float)) or not math.isfinite(sensitivity) or not .5 <= sensitivity <= 4:
            raise ValueError("Unsupported dial settings")
        if (response, sensitivity) == (self.response, self.sensitivity):
            return
        self.response, self.sensitivity = response, sensitivity
        self.fingers["index"] = False
        self.pressed_at.pop("index", None)
        self.release("Settings changed · pinch again")
        self.publish(True)

    def release(self, reason):
        self.active = False
        self.reason = reason
        self.integral = [0., 0., 0.]
        self.axis = None
        self.remainder = 0.

    def publish(self, force=False):
        now = self.clock()
        if not force and now - self.last_publish < .05:
            return
        self.last_publish = now
        while self.recent_gestures and now - self.recent_gestures[0][0] > 1:
            self.recent_gestures.popleft()
        self.emit("interaction_state", value=self.value, engaged=self.active, hand=self.hand, hand_error=self.hand_error,
                  fingers=dict(self.fingers), rotation=list(self.rotation),
                  gesture_count=self.gestures, steps=self.steps,
                  last_gesture=self.last_gesture, reason=self.reason,
                  recent_gestures=[dict(gesture, age_ms=round((now-at)*1000))
                                   for at, gesture in self.recent_gestures],
                  motion_fresh=self.last_gyro_at is not None and now-self.last_gyro_at < .35,
                  response=self.response, sensitivity=self.sensitivity,
                  orientation_kind="relative_gyro_experimental")

    def tick(self):
        now = self.clock()
        stale = self.last_gyro_at is not None and now - self.last_gyro_at >= .35
        expired = [f for f, at in self.pressed_at.items() if now-at >= 10]
        if stale and (self.active or any(self.fingers.values())):
            self.fingers = dict.fromkeys(self.fingers, False)
            self.pressed_at.clear()
            self.release("Motion paused · pinch again to resume")
            self.publish(True)
        for finger in expired:
            self.fingers[finger] = False
            self.pressed_at.pop(finger, None)
            if finger == "index":
                self.release("Hold timed out · release and pinch again")
            self.publish(True)

    def feed(self, event, **data):
        self.tick()
        now = self.clock()
        if event == "gesture":
            self.gestures += 1
            self.last_gesture = {k: data[k] for k in ("finger", "action", "derived_action", "synthetic")}
            # Preserve brief gestures that begin and end between browser polls.
            self.recent_gestures.append((now, dict(self.last_gesture, id=self.gestures)))
            finger = data["finger"]
            if not data["synthetic"] and finger in self.fingers:
                # Raw press/release and derived button events arrive in pairs.
                press = data["action"] == "press" or data["derived_action"] == "buttonPress"
                release = data["action"] == "release" or data["derived_action"] in ("buttonRelease", "buttonHoldRelease")
                if press and not self.fingers[finger]:
                    self.fingers[finger] = True
                    self.pressed_at[finger] = now
                    if finger == "index" and self.hand is not None and self.last_gyro_at is not None and now-self.last_gyro_at < .35:
                        self.release("Pinched · rotate your wrist")
                        self.active = True
                if release:
                    self.fingers[finger] = False
                    self.pressed_at.pop(finger, None)
                    if finger == "index":
                        self.release("Released · pinch to turn the dial")
            self.publish(True)
        elif event == "gyro_sample":
            stamp, values = data["timestamp_us"], data["values"]
            dt = None if self.last_device_time is None else (stamp-self.last_device_time)/1e6
            self.last_device_time = stamp
            self.last_gyro_at = now
            if dt is None or not 0 < dt <= .05:
                if self.active:
                    self.fingers["index"] = False
                    self.pressed_at.pop("index", None)
                    self.release("Motion gap · pinch again to resume")
                self.publish()
                return
            # Update bias only when nearly stationary and no pinch is held.
            if not any(self.fingers.values()) and max(abs(v-b) for v, b in zip(values, self.bias)) < 45:
                alpha = 1-math.exp(-dt/2)
                self.bias = [b + alpha*(v-b) for b, v in zip(self.bias, values)]
            delta = [(v-b)*self.gyro_scale*dt for v, b in zip(values, self.bias)]
            radians = [math.radians(v) for v in delta]
            angle = math.sqrt(sum(v*v for v in radians))
            if angle:
                dq = [math.cos(angle/2)] + [v*math.sin(angle/2)/angle for v in radians]
                self.rotation = multiply(self.rotation, dq)
                norm = math.sqrt(sum(v*v for v in self.rotation))
                self.rotation = [v/norm for v in self.rotation]
            if self.active:
                # Wrist mirroring changes the dial sign, not gesture labels or IMU pose.
                polarity = -1 if self.hand == "left" else 1
                self.integral = [v+d for v, d in zip(self.integral, delta)]
                if self.axis is None and max(map(abs, self.integral)) >= 1:
                    self.axis = max(range(3), key=lambda i: abs(self.integral[i]))
                    if self.response == "direct":
                        self.remainder = self.integral[self.axis]*self.sensitivity*polarity
                elif self.axis is not None and self.response == "direct":
                    self.remainder += delta[self.axis]*self.sensitivity*polarity
                if self.axis is not None and self.response == "rate":
                    tilt = self.integral[self.axis]
                    # A small dead zone allows a held pinch to rest at neutral.
                    speed = math.copysign(min(40., max(0., abs(tilt)-3)*3)*self.sensitivity, tilt)
                    self.remainder += speed*dt*polarity
                step = math.trunc(self.remainder)
                if step:
                    previous = self.value
                    self.value = max(0, min(100, self.value+step))
                    self.remainder -= step
                    self.steps += abs(self.value-previous)
                if (self.value == 0 and self.remainder < 0) or (self.value == 100 and self.remainder > 0):
                    self.remainder = 0.
            elif self.reason == "Waiting for motion":
                self.reason = "Ready · pinch thumb and index to turn the dial"
            self.publish()

    def finish(self):
        self.fingers = dict.fromkeys(self.fingers, False)
        self.pressed_at.clear()
        self.release("Session ended")
        self.last_gyro_at = None
        self.publish(True)
