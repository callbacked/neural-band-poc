import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { GLTFLoader } from './dashboard/vendor/GLTFLoader.js';
import { Vector3, Box3 } from './dashboard/vendor/three.module.js';
import { buildHandModel } from './dashboard/hand-model.js';

const file = readFileSync(new URL('./dashboard/models/right-hand.glb', import.meta.url));
const gltf = await new GLTFLoader().parseAsync(file.buffer.slice(file.byteOffset, file.byteOffset + file.byteLength), '');
const model = buildHandModel(gltf.scene);
const joints = {};
gltf.scene.traverse(node => { if (node.isBone) joints[node.name] = node; });
const position = name => joints[name].getWorldPosition(new Vector3());

model.pose(0, 0, 'right');
const restIndex = position('index-finger-tip');
const restPinky = position('pinky-finger-tip');
const restRing = position('ring-finger-tip');
const restGap = position('thumb-tip').distanceTo(restIndex);
for (const finger of ['index', 'middle']) {
  model.pose(finger === 'index' ? 1 : 0, finger === 'middle' ? 1 : 0, 'right');
  assert.ok(position('thumb-tip').distanceTo(position(`${finger}-finger-tip`)) < .01 * 18,
    `${finger} pinch should bring the fingertip pads together`);
  assert.ok(position('pinky-finger-tip').distanceTo(restPinky) < 1e-6);
  assert.ok(position('ring-finger-tip').distanceTo(restRing) < 1e-6);
  const bounds = new Box3().setFromObject(model.root, true);
  assert.ok([...bounds.min, ...bounds.max].every(Number.isFinite));
  assert.ok(bounds.getSize(new Vector3()).length() < 6, 'Skin should remain within human hand proportions');
}
model.pose(0, 0, 'right');
assert.ok(position('index-finger-tip').distanceTo(restIndex) < 1e-6);
assert.ok(Math.abs(position('thumb-tip').distanceTo(restIndex) - restGap) < 1e-6);
const strokes = {};
for (const direction of ['up', 'down', 'left', 'right']) {
  strokes[direction] = [];
  for (const progress of [0, .25, .5, .75, 1]) {
    model.pose(0, 0, 'right', {direction, progress, weight: 1});
    const thumb = position('thumb-tip');
    strokes[direction].push(thumb);
    assert.ok(thumb.distanceTo(position('index-finger-tip')) < .025*18, 'Swipe must stay near the index pad');
    assert.ok(position('pinky-finger-tip').distanceTo(restPinky) < 1e-6);
    assert.ok(position('ring-finger-tip').distanceTo(restRing) < 1e-6);
  }
  assert.ok(strokes[direction][0].distanceTo(strokes[direction][4]) > .005*18, 'The thumb must visibly travel');
}
for (const [a, b] of [['up', 'down'], ['left', 'right']]) {
  assert.ok(strokes[a][0].distanceTo(strokes[b][4]) < 1e-6);
  assert.ok(strokes[a][4].distanceTo(strokes[b][0]) < 1e-6);
}
model.pose(0, 0, 'right');
assert.ok(position('index-finger-tip').distanceTo(restIndex) < 1e-6);
model.pose(0, 0, 'left');
const mirrored = position('index-finger-tip');
assert.ok(Math.abs(mirrored.x + restIndex.x) < 1e-6);
assert.ok(Math.abs(mirrored.y - restIndex.y) < 1e-6);
console.log('Hand mesh: both pinches close, release restores the pose, untracked fingers stay still, mirror is correct.');
