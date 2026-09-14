import assert from 'node:assert/strict';
import { GestureAnimator } from '../static/gesture-animation.js';

const event = (id, action, derived = 'unknown', finger = 'index', extra = {}) =>
  ({id, finger, action, derived_action: derived, synthetic: false, age_ms: 0, ...extra});
const packet = (events, extra = {}) => ({session: 'test', live: true, fingers: {}, recent_gestures: events, ...extra});

const taps = new GestureAnimator();
const quick = packet([event(1, 'press'), event(2, 'unknown', 'buttonPress'), event(3, 'release'), event(4, 'unknown', 'singleTap')]);
taps.ingest(quick, 0);
assert.ok(taps.sample(90).index > .99, 'A complete tap between polls must still be visible');
taps.ingest(quick, 100);
assert.equal(taps.sample(230).index, 0, 'Polling the same IDs must not replay the tap');
assert.equal(taps.label, 'Index single tap');

const double = new GestureAnimator();
double.ingest(packet([event(1, 'doubletap', 'unknown', 'middle')]), 0);
double.ingest(packet([event(2, 'unknown', 'doubleTap', 'middle')]), 100);
assert.equal(double.sample(90).middle, 1);
assert.equal(double.sample(240).middle, 0, 'Double tap needs a visible release between contacts');
assert.equal(double.sample(360).middle, 1);
assert.equal(double.sample(550).middle, 0, 'Raw + derived double tap must produce only two beats');

const physicalDouble = new GestureAnimator();
physicalDouble.ingest(packet([event(1, 'press'), event(2, 'release')]), 0);
physicalDouble.ingest(packet([event(3, 'press'), event(4, 'release'), event(5, 'unknown', 'doubleTap')]), 150);
assert.equal(physicalDouble.sample(360).index, 1);
assert.equal(physicalDouble.sample(600).index, 0, 'A double-tap classification must not replay the two physical presses');

const hold = new GestureAnimator();
hold.ingest(packet([event(1, 'press'), event(2, 'unknown', 'buttonHold')], {fingers: {index: true}}), 0);
assert.equal(hold.sample(1000).index, 1);
assert.equal(hold.label, 'Index press + hold');
hold.ingest(packet([event(3, 'release')]), 1000);
assert.equal(hold.sample(1100).index, 0);

for (const direction of ['up', 'down', 'left', 'right']) {
  const swipe = new GestureAnimator();
  swipe.ingest(packet([event(1, direction, 'unknown', 'thumb')]), 0);
  const before = swipe.sample(110).swipe;
  swipe.ingest(packet([event(2, 'unknown', `button${direction[0].toUpperCase()}${direction.slice(1)}`, 'thumb')]), 60);
  const after = swipe.sample(290).swipe;
  assert.equal(after.direction, direction);
  assert.ok(after.progress > before.progress);
  assert.equal(swipe.sample(640).swipe, null, 'Derived direction must not restart the swipe');
}

const repeat = new GestureAnimator();
repeat.ingest(packet([event(1, 'left', 'unknown', 'thumb')]), 0);
const contact = repeat.sample(280).swipe.weight;
repeat.ingest(packet([event(2, 'left', 'unknown', 'thumb')]), 280);
assert.equal(repeat.sample(280).swipe.weight, contact, 'Repeated swipes must not snap the index finger open');
assert.equal(repeat.sample(400).swipe.weight, 1);

const stale = new GestureAnimator();
stale.ingest(packet([event(1, 'press', 'unknown', 'index', {synthetic: true}), event(2, 'tap', 'unknown', 'index', {age_ms: 800})]), 0);
assert.equal(stale.sample(90).index, 0);
stale.ingest(packet([event(3, 'press')], {fingers: {index: true}}), 100);
stale.ingest(packet([event(3, 'press')], {live: false}), 120);
assert.equal(stale.sample(190).index, 0);
stale.ingest(packet([event(3, 'press')]), 200);
assert.equal(stale.sample(290).index, 0, 'Recovery must not replay IDs seen before the stall');
stale.ingest(packet([event(1, 'tap')], {session: 'next'}), 300);
assert.equal(stale.sample(390).index, 1, 'A new session must accept its own event IDs');
console.log('Gesture animation: brief taps, double taps, holds, four swipes, deduplication and freshness passed.');
