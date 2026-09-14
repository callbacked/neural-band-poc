"""Drive the dial through the same fragmented wire parser as the live client."""

import struct
import unittest

from input_service import InputService
from mac_band_probe import typed_frame, field


class PinchDialTests(unittest.TestCase):
    def setUp(self):
        self.now = 0.
        self.sequence = 0
        self.states = []
        self.reader = InputService(lambda event, **data: self.states.append(data) if event == 'interaction_state' else None,
                                   requested_fields=(3,6,8))
        self.reader.interaction.clock = lambda: self.now
        self.reader.interaction.set_hand('right')
        self.motion(0, 1)

    def wire(self, kind, payload):
        frame = typed_frame(5, [kind], payload)
        for offset in range(0, len(frame), 7):
            part = frame[offset:offset+7]
            padding = -len(part) % 16
            self.reader.feed(part+bytes([0xc0+padding])*padding)

    def gesture(self, finger=2, action=1, derived=0, synthetic=0):
        self.wire(0x0200020d, b''.join(field(n,v) for n,v in [(1,1),(2,1789360339000000),(3,finger),(4,action),(5,derived),(12,synthetic)]))

    def motion(self, rate, samples=100):
        for _ in range(samples):
            self.now += .01
            self.sequence += 1
            self.wire(0x0200020f, field(1,self.sequence)+field(2,round(self.now*1e6))+field(3,struct.pack('<3h',rate,0,0)))

    def state(self):
        self.reader.interaction.publish(True)
        return self.states[-1]

    def test_only_held_index_changes_dial_and_duplicate_press_does_not_rebase(self):
        self.motion(1000, 20)
        self.assertEqual(self.state()['value'], 50)
        self.gesture()
        self.motion(1000, 10)
        self.assertEqual(self.state()['value'], 57)

        self.gesture(action=0, derived=9)
        self.motion(1000, 10)
        self.assertEqual(self.state()['value'], 64)
        self.gesture(action=2)
        self.motion(1000, 50)
        self.assertEqual(self.state()['value'], 64)
        self.assertFalse(self.state()['engaged'])
        self.gesture()
        self.motion(-1000, 10)
        self.assertEqual(self.state()['value'], 57)

    def test_left_hand_reverses_only_dial_for_both_response_modes(self):
        for response in ('direct', 'rate'):
            values, rotations = [], []
            for hand in ('right', 'left'):
                self.setUp()
                self.reader.interaction.set_hand(hand)
                self.reader.interaction.configure(response=response)
                self.gesture(finger=1, action=9)
                self.assertEqual(self.state()['last_gesture']['action'], 'right')
                self.gesture()
                self.motion(1000, 20)
                self.motion(0, 10)
                values.append(self.state()['value'])
                rotations.append(self.state()['rotation'])
            self.assertGreater(values[0], 50)
            self.assertEqual(values[1], 100-values[0])
            self.assertEqual(rotations[0], rotations[1])

    def test_unconfirmed_hand_cannot_turn_dial_and_confirmation_needs_a_new_pinch(self):
        self.reader.interaction.set_hand(None)
        self.gesture()
        self.motion(1000, 10)
        self.assertEqual(self.state()['value'], 50)
        self.assertFalse(self.state()['engaged'])
        self.reader.interaction.set_hand('left')
        self.motion(1000, 10)
        self.assertEqual(self.state()['value'], 50)
        self.gesture()
        self.motion(1000, 10)
        self.assertEqual(self.state()['value'], 43)

    def test_synthetic_and_middle_presses_do_not_engage_index_dial(self):
        self.gesture(synthetic=1)
        self.gesture(finger=3)
        self.motion(1000, 30)
        self.assertEqual(self.state()['value'], 50)
        self.assertEqual(self.state()['fingers'], {'index':False,'middle':True})

    def test_receive_stall_and_device_time_gap_cancel_hold(self):
        self.gesture()
        self.motion(1000, 10)
        value = self.state()['value']
        self.now += .4
        self.reader.tick()
        self.assertFalse(self.state()['engaged'])
        self.motion(1000, 30)
        self.assertEqual(self.state()['value'], value)
        self.gesture()
        self.wire(0x0200020f, field(1,1000)+field(2,100000000)+field(3,struct.pack('<3h',1000,0,0)))
        self.assertFalse(self.state()['engaged'])

    def test_clamping_and_shutdown_leave_a_released_hand(self):
        self.gesture()
        self.motion(20000, 30)
        self.assertEqual(self.state()['value'], 100)
        self.motion(-1000, 10)
        self.assertEqual(self.state()['value'], 93)
        self.reader.finish()
        self.assertFalse(self.states[-1]['engaged'])
        self.assertFalse(self.states[-1]['motion_fresh'])
        self.assertEqual(self.states[-1]['fingers'], {'index':False,'middle':False})

    def test_lost_release_times_out_and_quaternion_stays_normalized(self):
        self.gesture()
        self.motion(100, 1010)
        state = self.state()
        self.assertFalse(state['engaged'])
        self.assertAlmostEqual(sum(x*x for x in state['rotation']),1)

    def test_hold_to_adjust_continues_at_a_fixed_twist_until_release(self):
        self.reader.interaction.configure(response='rate', sensitivity=1)
        self.gesture()
        self.motion(1000,20)
        initial = self.state()['value']
        self.motion(0,100)
        self.assertGreaterEqual(self.state()['value']-initial,32)
        self.assertLessEqual(self.state()['value']-initial,34)
        self.gesture(action=2)
        final = self.state()['value']
        self.motion(0,100)
        self.assertEqual(self.state()['value'],final)

    def test_sensitivity_setting_releases_current_hold_and_applies_to_next(self):
        self.gesture()
        self.reader.interaction.configure(sensitivity=2)
        self.assertFalse(self.state()['engaged'])
        self.gesture()
        self.motion(1000,10)
        self.assertEqual(self.state()['value'],64)

    def test_invalid_sensitivity_is_rejected(self):
        for value in [0,5,float('nan'),'2']:
            with self.assertRaises(ValueError):
                self.reader.interaction.configure(sensitivity=value)

    def test_short_gestures_survive_until_the_browser_poll_and_then_expire(self):
        self.gesture()
        self.gesture(action=2)
        self.motion(0, 10)
        events = self.state()['recent_gestures']
        self.assertEqual([(g['id'], g['action'], g['finger']) for g in events],
                         [(1, 'press', 'index'), (2, 'release', 'index')])
        self.assertAlmostEqual(events[0]['age_ms'], 100)
        self.assertFalse(self.state()['fingers']['index'])
        self.motion(0, 100)
        self.assertEqual(self.state()['recent_gestures'], [])


if __name__ == '__main__':
    unittest.main()
