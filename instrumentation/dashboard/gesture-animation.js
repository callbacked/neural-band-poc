const directions = {buttonUp: 'up', buttonDown: 'down', buttonLeft: 'left', buttonRight: 'right'};
const arrows = {up: '↑', down: '↓', left: '←', right: '→'};
const clamp = value => Math.max(0, Math.min(1, value));
const smooth = value => { const t = clamp(value); return t*t*(3-2*t); };
const contactWeight = (swipe, now) => {
  const elapsed = now-swipe.start;
  return (swipe.startWeight+(1-swipe.startWeight)*smooth(elapsed/180)) *
    (1-smooth((elapsed-380)/250));
};

// Events can arrive as a raw action followed by its derived equivalent.
// Keep a short visual beat for taps without slowing the actual band/dial input.
export class GestureAnimator {
  constructor() {
    this.session = null;
    this.cursor = 0;
    this.clear();
  }

  clear() {
    this.fingers = Object.fromEntries(['index', 'middle'].map(finger => [finger, {
      down: false, beats: [], unconfirmedPress: null, semantic: null,
    }]));
    this.swipe = null;
    this.lastSwipe = null;
    this.label = 'Waiting for recognized input';
  }

  beat(state, now) {
    state.beats = state.beats.filter(at => now-at < 650);
    const last = state.beats.at(-1);
    const start = last === undefined ? now : Math.max(now, last+270);
    // Favor current input if a burst would otherwise build a visual backlog.
    if (start-now > 540) state.beats = [now];
    else state.beats.push(start);
  }

  ingest(packet, now) {
    if (packet.session !== this.session) {
      this.session = packet.session;
      this.cursor = 0;
      this.clear();
    }
    if (!packet.live) this.clear();
    for (const event of packet.recent_gestures || []) {
      if (!Number.isInteger(event.id) || event.id <= this.cursor) continue;
      this.cursor = event.id;
      if (!packet.live || event.synthetic || event.age_ms < 0 || event.age_ms > 350) continue;
      const direction = directions[event.derived_action] || (arrows[event.action] ? event.action : null);
      const source = event.derived_action !== 'unknown' ? 'derived' : 'raw';
      if (event.finger === 'thumb' && direction) {
        const duplicate = this.lastSwipe && this.lastSwipe.direction === direction &&
          this.lastSwipe.source !== source && now-this.lastSwipe.at < 160;
        if (!duplicate) {
          const startWeight = this.swipe ? contactWeight(this.swipe, now) : 0;
          this.swipe = {direction, start: now, startWeight};
          this.lastSwipe = {direction, source, at: now};
          this.label = `Thumb swipe · ${arrows[direction]} ${direction}`;
        }
        continue;
      }
      const state = this.fingers[event.finger];
      if (!state) continue;
      const name = event.finger === 'index' ? 'Index' : 'Middle';
      const action = event.action, derived = event.derived_action;
      if (action === 'press' || derived === 'buttonPress') {
        if (!state.down) {
          this.beat(state, now);
          state.unconfirmedPress = now;
        }
        state.down = true;
        this.label = `${name} pinch`;
      } else if (action === 'release' || ['buttonRelease', 'buttonHoldRelease'].includes(derived)) {
        state.down = false;
        if (!state.semantic || now-state.semantic.at > 650) this.label = `${name} pinch · released`;
      } else if (derived === 'buttonHold') {
        state.down = true;
        this.label = `${name} press + hold`;
      } else {
        const kind = derived === 'doubleTap' || action === 'doubletap' ? 'double'
          : derived === 'singleTap' || action === 'tap' ? 'single' : null;
        if (!kind) continue;
        const duplicate = state.semantic?.kind === kind && state.semantic.source !== source &&
          now-state.semantic.at < 160;
        if (duplicate) continue;
        if (kind === 'double') {
          const beats = state.beats.filter(at => now-at < 650).length;
          for (let i = beats; i < 2; i++) this.beat(state, now);
        } else if (state.unconfirmedPress === null || now-state.unconfirmedPress > 650) {
          this.beat(state, now);
        }
        state.unconfirmedPress = null;
        state.semantic = {kind, source, at: now};
        this.label = `${name} ${kind} tap`;
      }
    }
    // This snapshot also covers starting the page during an existing hold.
    for (const finger of ['index', 'middle']) this.fingers[finger].down = Boolean(packet.live && packet.fingers?.[finger]);
  }

  sample(now) {
    const pose = {index: 0, middle: 0, swipe: null};
    for (const [finger, state] of Object.entries(this.fingers)) {
      pose[finger] = state.down ? 1 : 0;
      for (const start of state.beats) {
        const elapsed = now-start;
        const amount = elapsed < 130 ? smooth(elapsed/70) : 1-smooth((elapsed-130)/90);
        pose[finger] = Math.max(pose[finger], amount);
      }
      state.beats = state.beats.filter(at => now-at < 650);
    }
    if (this.swipe) {
      const elapsed = now-this.swipe.start;
      if (elapsed < 630) {
        pose.swipe = {direction: this.swipe.direction, progress: smooth((elapsed-100)/200),
          weight: contactWeight(this.swipe, now)};
      } else this.swipe = null;
    }
    return pose;
  }
}
