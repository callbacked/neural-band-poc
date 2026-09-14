import * as THREE from './vendor/three.module.js';

// The WebXR asset supplies one continuous skin and 25 joint transforms.
// Pinches below are illustrative poses; the band does not supply joint angles.
export function buildHandModel(asset) {
  const bones = {};
  asset.traverse(object => {
    if (object.isBone) bones[object.name] = object;
    if (object.isSkinnedMesh) {
      object.material = new THREE.MeshStandardMaterial({
        color: 0xe9e6f1, roughness: .64, metalness: 0,
      });
      object.castShadow = true;
      object.receiveShadow = true;
      // The original open-hand bounds do not enclose every posed finger.
      object.frustumCulled = false;
    }
  });
  if (!bones.wrist || !bones['index-finger-tip']) throw Error('Hand asset has no usable joint rig');

  asset.updateMatrixWorld(true);
  const wristOrigin = bones.wrist.getWorldPosition(new THREE.Vector3());
  const chains = {
    thumb: ['thumb-metacarpal', 'thumb-phalanx-proximal', 'thumb-phalanx-distal', 'thumb-tip'],
  };
  for (const finger of ['index', 'middle', 'ring', 'pinky']) {
    chains[finger] = ['metacarpal', 'phalanx-proximal', 'phalanx-intermediate', 'phalanx-distal', 'tip']
      .map(joint => `${finger}-finger-${joint}`);
  }
  // WebXR joints are siblings because tracking normally supplies world poses.
  // Reparent with attach() to preserve their bind transforms for local posing.
  for (const chain of Object.values(chains)) {
    let parent = bones.wrist;
    for (const name of chain) {
      parent.attach(bones[name]);
      parent = bones[name];
    }
  }
  const neutral = Object.fromEntries(Object.entries(bones).map(([name, bone]) => [name, bone.quaternion.clone()]));
  function reset() {
    for (const [name, bone] of Object.entries(bones)) bone.quaternion.copy(neutral[name]);
    asset.updateMatrixWorld(true);
  }
  function rotateWorld(bone, delta) {
    const world = delta.clone().multiply(bone.getWorldQuaternion(new THREE.Quaternion()));
    const parent = bone.parent.getWorldQuaternion(new THREE.Quaternion());
    bone.quaternion.copy(parent.invert().multiply(world));
    asset.updateMatrixWorld(true);
  }
  function pinchPose(finger) {
    reset();
    const joints = chains[finger].slice(1, 4);
    const angles = finger === 'index' ? [.85, 1.3, .9] : [1., 1.35, .8];
    joints.forEach((name, i) => rotateWorld(bones[name],
      new THREE.Quaternion().setFromAxisAngle(new THREE.Vector3(0, 0, 1), -angles[i])));

    const target = bones[`${finger}-finger-tip`].getWorldPosition(new THREE.Vector3());
    // A little pad separation keeps the skin surfaces from passing through.
    target.z -= .005;
    solveThumb(target);
    return snapshot();
  }
  const snapshot = () => Object.fromEntries(Object.entries(bones).map(([name, bone]) => [name, bone.quaternion.clone()]));
  function solveThumb(target) {
    const tip = bones['thumb-tip'];
    for (let pass = 0; pass < 24; pass++) {
      if (tip.getWorldPosition(new THREE.Vector3()).distanceTo(target) < .001) break;
      for (const name of chains.thumb.slice(0, -1).reverse()) {
        const joint = bones[name], pivot = joint.getWorldPosition(new THREE.Vector3());
        const towardTip = tip.getWorldPosition(new THREE.Vector3()).sub(pivot).normalize();
        const towardTarget = target.clone().sub(pivot).normalize();
        const turn = new THREE.Quaternion().setFromUnitVectors(towardTip, towardTarget);
        const angle = 2 * Math.acos(THREE.MathUtils.clamp(turn.w, -1, 1));
        if (angle > .2) turn.identity().slerp(new THREE.Quaternion().setFromUnitVectors(towardTip, towardTarget), .2 / angle);
        rotateWorld(joint, turn);
      }
    }
  }
  const pinches = {index: pinchPose('index'), middle: pinchPose('middle')};
  const swipes = {};
  for (const axis of ['horizontal', 'vertical']) {
    swipes[axis] = [];
    for (let step = 0; step <= 4; step++) {
      for (const [name, bone] of Object.entries(bones)) bone.quaternion.copy(pinches.index[name]);
      asset.updateMatrixWorld(true);
      const tip = bones['index-finger-tip'].getWorldPosition(new THREE.Vector3());
      const distal = bones['index-finger-phalanx-distal'].getWorldPosition(new THREE.Vector3());
      const along = tip.clone().sub(distal).normalize();
      if (along.y < 0) along.negate();
      const target = distal.lerp(tip, .65);
      target.z -= .005;
      const offset = step/2-1;
      if (axis === 'horizontal') target.addScaledVector(along, offset*.007);
      else target.z += offset*.004;
      solveThumb(target);
      swipes[axis].push(snapshot());
    }
  }
  reset();

  // Native asset: finger length is -Y, palm width is Z, depth is X.
  const root = new THREE.Group(), mirror = new THREE.Group(), basis = new THREE.Group();
  basis.quaternion.setFromRotationMatrix(new THREE.Matrix4().set(
    0, 0, 1, 0,
    0, -1, 0, 0,
    1, 0, 0, 0,
    0, 0, 0, 1,
  ));
  basis.scale.setScalar(18);
  asset.position.sub(wristOrigin);
  basis.add(asset); mirror.add(basis); root.add(mirror);

  return {
    root,
    pose(index, middle, hand, swipe = null) {
      mirror.scale.x = hand === 'left' ? -1 : 1;
      for (const [name, bone] of Object.entries(bones)) {
        const amount = name.startsWith('thumb') ? Math.max(index, middle)
          : name.startsWith('index-') ? index : name.startsWith('middle-') ? middle : 0;
        const pose = name.startsWith('middle-') || (name.startsWith('thumb') && middle > index)
          ? pinches.middle : pinches.index;
        bone.quaternion.copy(neutral[name]).slerp(pose[name], amount);
      }
      if (swipe) {
        const horizontal = ['left', 'right'].includes(swipe.direction);
        const frames = swipes[horizontal ? 'horizontal' : 'vertical'];
        const forward = ['left', 'up'].includes(swipe.direction);
        const progress = THREE.MathUtils.clamp(forward ? swipe.progress : 1-swipe.progress, 0, 1)*4;
        const frame = Math.min(3, Math.floor(progress));
        for (const [name, bone] of Object.entries(bones)) {
          if (!name.startsWith('thumb') && !name.startsWith('index-')) continue;
          const target = frames[frame][name].clone().slerp(frames[frame+1][name], progress-frame);
          bone.quaternion.slerp(target, swipe.weight);
        }
      }
      root.updateMatrixWorld(true);
    },
  };
}
