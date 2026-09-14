import * as THREE from '/vendor/three.module.js';
import { GLTFLoader } from '/vendor/GLTFLoader.js';
import { buildHandModel } from '/hand-model.js';
import { GestureAnimator } from '/gesture-animation.js';

(() => {
  const el = id => document.getElementById(id);
  const canvas = el('hand-canvas');
  let renderer;
  try { renderer = new THREE.WebGLRenderer({canvas, antialias:true, alpha:true}); }
  catch { el('hand-error').textContent = 'The 3D view needs WebGL. Enable hardware acceleration in your browser and refresh.'; el('hand-error').hidden = false; return; }
  renderer.setPixelRatio(Math.min(devicePixelRatio || 1, 2));
  renderer.setClearColor(0x111719, 1);
  renderer.shadowMap.enabled = true;
  renderer.shadowMap.type = THREE.PCFSoftShadowMap;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.05;
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(38, 1, .1, 50);
  const aim = new THREE.Vector3(0, 0, 0);
  const flat = new THREE.Quaternion().setFromEuler(new THREE.Euler(-Math.PI/2, 0, Math.PI/2));
  let azimuth = -.15, elevation = .65, dragging = null;
  let distance = 7.4;
  function cameraView() { camera.position.set(Math.sin(azimuth)*Math.cos(elevation)*distance, aim.y+Math.sin(elevation)*distance, Math.cos(azimuth)*Math.cos(elevation)*distance); camera.lookAt(aim); }
  cameraView();
  canvas.addEventListener('pointerdown', e => { dragging=[e.clientX,e.clientY];canvas.setPointerCapture(e.pointerId); });
  canvas.addEventListener('pointermove', e => { if (!dragging) return; azimuth-=(e.clientX-dragging[0])*.008; elevation=Math.max(-1.1,Math.min(1.1,elevation+(e.clientY-dragging[1])*.008)); dragging=[e.clientX,e.clientY];cameraView(); });
  canvas.addEventListener('pointerup', () => { dragging=null; });
  canvas.addEventListener('pointercancel', () => { dragging=null; });
  canvas.addEventListener('keydown', e => { if (!['ArrowLeft','ArrowRight','ArrowUp','ArrowDown'].includes(e.key)) return;e.preventDefault();if(e.key==='ArrowLeft')azimuth-=.15;if(e.key==='ArrowRight')azimuth+=.15;if(e.key==='ArrowUp')elevation=Math.min(1.1,elevation+.15);if(e.key==='ArrowDown')elevation=Math.max(-1.1,elevation-.15);cameraView(); });
  scene.add(new THREE.HemisphereLight(0xefedff,0x30303d,2.1));
  const key = new THREE.DirectionalLight(0xffffff,3.2);key.position.set(-3,5,5);key.castShadow=true;key.shadow.mapSize.set(1024,1024);scene.add(key);
  const rim = new THREE.DirectionalLight(0xa699ec,2.2);rim.position.set(3,2,-3);scene.add(rim);
  let model = null;
  el('hand-loading').hidden = false;
  new GLTFLoader().loadAsync('/models/right-hand.glb').then(gltf => {
    model = buildHandModel(gltf.scene);
    model.pose(0, 0, 'right');
    model.root.position.x = 1.35;
    scene.add(model.root);
    el('hand-loading').hidden = true;
  }).catch(error => {
    el('hand-loading').hidden = true;
    el('hand-error').textContent = `The hand model could not load: ${error.message}. Refresh to retry.`;
    el('hand-error').hidden = false;
  });
  let packet = {}, lastReceived = 0, session = null;
  let rotation = [1, 0, 0, 0], reference = [1, 0, 0, 0];
  const curls = {index: 0, middle: 0};
  let previousFrame = 0;
  let settingsLoaded = false;
  const animator = new GestureAnimator();
  async function saveSettings() {
    const settings={response:el('dial-response').value,sensitivity:Number(el('dial-sensitivity').value)};
    try {
      const response=await fetch('/api/dial-settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(settings)});
      const result=await response.json();if(!response.ok)throw Error(result.error);
      el('settings-status').textContent='Saved · release and pinch again to use these settings';
    } catch(error) { el('settings-status').textContent=`Settings not saved: ${error.message}`; }
  }
  el('dial-response').addEventListener('change',saveSettings);
  el('dial-sensitivity').addEventListener('input',()=>{el('sensitivity-value').textContent=`${el('dial-sensitivity').value}×`;});
  el('dial-sensitivity').addEventListener('change',saveSettings);
  let savingHand = false, handError = null;
  el('band-hand').addEventListener('change', async () => {
    savingHand = true;
    el('band-hand').disabled = true;
    handError = null;
    try {
      const response = await fetch('/api/hand', {method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify({hand:el('band-hand').value || null})});
      const result = await response.json();
      if (!response.ok) throw Error(result.error);
    } catch (error) { handError = error.message; }
    finally { savingHand = false; }
  });
  const mul = (a, b) => {
    const [w,x,y,z] = a, [v,i,j,k] = b;
    return [w*v-x*i-y*j-z*k, w*i+x*v+y*k-z*j, w*j-x*k+y*v+z*i, w*k+x*j-y*i+z*v];
  };
  const inverse = q => [q[0], -q[1], -q[2], -q[3]];
  el('recenter-hand').addEventListener('click', () => { reference = inverse(packet.rotation || [1,0,0,0]); rotation = [1,0,0,0]; azimuth=-.15;elevation=.65;cameraView(); });
  const live = () => packet.live && performance.now()-lastReceived < 500;

  async function poll() {
    try {
      const response = await fetch('/api/interaction');
      if (!response.ok) throw Error('Listener unavailable');
      packet = await response.json();
      if (!savingHand) el('band-hand').value = packet.requested_hand || '';
      el('band-hand').disabled = savingHand || packet.running;
      el('hand-setting-status').textContent = handError || packet.hand_error || (packet.listening
        ? packet.hand ? `${packet.hand === 'left' ? 'Left' : 'Right'} hand · confirmed by your band`
          : 'Checking the band hand setting…'
        : 'Changes apply when you press Start. Stop the session to change hands.');
      if (!settingsLoaded && packet.settings) {
        el('dial-response').value=packet.settings.response;
        el('dial-sensitivity').value=packet.settings.sensitivity;
        el('sensitivity-value').textContent=`${packet.settings.sensitivity}×`;
        settingsLoaded=true;
      }
      lastReceived = performance.now();
      if (session !== packet.session) {
        session = packet.session;
        reference = inverse(packet.rotation || [1,0,0,0]); rotation = [1,0,0,0];
      }
      animator.ingest(packet, lastReceived);
      const value = Number.isFinite(packet.value) ? packet.value : 50;
      el('dial-value').textContent = value;
      const angle = value / 100 * 270 - 135, radians = (angle-90)*Math.PI/180;
      const start = -225*Math.PI/180;
      el('dial-arc').setAttribute('d', value === 0 ? '' : `M ${120+92*Math.cos(start)} ${120+92*Math.sin(start)} A 92 92 0 ${value > 66.666 ? 1 : 0} 1 ${120+92*Math.cos(radians)} ${120+92*Math.sin(radians)}`);
      el('dial-pointer').setAttribute('transform', `rotate(${angle} 120 120)`);
      el('live-gestures').textContent = `${packet.gesture_count || 0} gesture messages`;
      el('dial-steps').textContent = `${packet.steps || 0} steps`;
    } catch {
      packet.live = false;
      el('band-hand').disabled = true;
    } finally {
      setTimeout(poll, 50);
    }
  }

  function draw(now) {
    const dt = Math.min(.1, (now-previousFrame)/1000 || .016); previousFrame = now;
    const fresh = live(), engaged = fresh && packet.engaged;
    if (!fresh) animator.clear();
    const pose = animator.sample(now);
    el('recognized-event').textContent = animator.label;
    const hand = packet.hand || packet.requested_hand || 'right';
    const emgSession = packet.stream_mode === 'raw-emg';
    el('hand-state').textContent = fresh ? `${packet.hand ? hand.toUpperCase() : 'HAND UNKNOWN'} · LIVE` : emgSession ? 'sEMG SESSION' : 'OFFLINE';
    el('pinch-status').textContent = fresh ? packet.reason : packet.listening ? 'Waiting for fresh band motion…'
      : emgSession ? 'Hand view is paused during sEMG recording' : 'Press Start when you’re ready';
    el('pinch-status').classList.toggle('engaged', Boolean(engaged));
    canvas.setAttribute('aria-label', `${hand} hand illustration. ${fresh ? animator.label : 'No live data'}.`);
    Object.keys(curls).forEach(f => { curls[f] += (pose[f]-curls[f])*(1-Math.exp(-dt*18)); });
    const target = fresh ? mul(reference, packet.rotation || [1,0,0,0]) : [1,0,0,0];
    const sign = rotation.reduce((s,v,i) => s+v*target[i], 0) < 0 ? -1 : 1;
    rotation = rotation.map((v,i) => v+(target[i]*sign-v)*(1-Math.exp(-dt*16)));
    const norm = Math.hypot(...rotation); rotation = rotation.map(v => v/norm);

    const width = canvas.clientWidth, height = 420;
    if (!width) { requestAnimationFrame(draw); return; }
    const size = renderer.getSize(new THREE.Vector2());
    if (size.x !== width || size.y !== height) { renderer.setSize(width,height,false);camera.aspect=width/height;distance=Math.max(7.4, 4.6/(2*Math.tan(THREE.MathUtils.degToRad(19))*camera.aspect));camera.updateProjectionMatrix();cameraView(); }
    if (model) {
      model.pose(curls.index, curls.middle, hand, pose.swipe);
      model.root.quaternion.copy(flat).multiply(new THREE.Quaternion(rotation[1],rotation[2],rotation[3],rotation[0]));
    }
    renderer.render(scene,camera);
    requestAnimationFrame(draw);
  }
  poll(); requestAnimationFrame(draw);
})();
