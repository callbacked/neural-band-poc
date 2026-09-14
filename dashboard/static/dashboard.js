'use strict';

const $ = id => document.getElementById(id);
let state = null;
let activeTab = 'direct';
let discoveryOptions = '';
let connectionSetupShown = false;
const clock = value => value ? new Date(value).toLocaleTimeString('en-US', {timeZone: 'America/New_York', hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit'}) : '—';
const preciseClock = value => value ? `${clock(value)}.${String(new Date(value).getUTCMilliseconds()).padStart(3, '0')}` : '—';
const bytes = value => new Intl.NumberFormat('en-US').format(value);
const svgText = (x, y, text, anchor = 'middle', cls = '') => `<text x="${x}" y="${y}" text-anchor="${anchor}" class="${cls}">${text}</text>`;

function emgChart(emg) {
  const container = $('emg-chart'), width = container.clientWidth;
  if (!width) return;
  const height = 370, left = 52, right = 18, top = 18, lane = 39;
  if (!emg.recent.length) {
    container.innerHTML = `<svg viewBox="0 0 ${width} ${height}">${svgText(width / 2, height / 2, 'No ADC samples in this session')}</svg>`;
    return;
  }
  const batches = emg.recent, channels = emg.config.channels;
  const points = batches.flatMap(batch => batch.samples.map((values, i) => ({
    t: batch.timestamp_us + i * 1e6 / emg.config.sample_rate, values,
    gap: i === 0 && batch.missing_before > 0
  })));
  const means = Array.from({length: channels}, (_, ch) => points.reduce((sum, p) => sum + p.values[ch], 0) / points.length);
  const span = Math.max(1, points[points.length - 1].t - points[0].t);
  const amplitude = Math.max(25, ...points.map(p => Math.max(...p.values.map((v, ch) => Math.abs(v - means[ch])))));
  let content = '';
  for (let ch = 0; ch < channels; ch++) {
    const baseline = top + lane * (ch + .5);
    content += `<line class="grid" x1="${left}" x2="${width-right}" y1="${baseline}" y2="${baseline}"/>${svgText(left-10, baseline+4, ch+1, 'end')}`;
    let path = '';
    points.forEach((point, i) => {
      const x = left + (point.t - points[0].t) / span * (width - left - right);
      const y = baseline - (point.values[ch] - means[ch]) / amplitude * lane * .43;
      const gap = i === 0 || point.gap || point.t <= points[i-1].t || point.t - points[i-1].t > 1000;
      path += `${gap ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)} `;
    });
    content += `<path d="${path}" class="emg-line"/>`;
  }
  content += svgText(left, height - 20, `Latest ${(span/1e6).toFixed(2)}s · shared scale ±${Math.ceil(amplitude)} ADC counts`, 'start');
  container.innerHTML = `<svg viewBox="0 0 ${width} ${height}">${content}</svg>`;
}

function trafficChart(session) {
  const container = $('traffic-chart');
  const width = container.clientWidth;
  if (!width) return;
  const height = 290, left = 62, right = 18, top = 24, bottom = 52;
  const plotWidth = Math.max(100, width - left - right), plotHeight = height - top - bottom;
  const start = session.started_at ? Date.parse(session.started_at) : 0;
  const end = state.running && state.phase === 'probing' ? Date.now() : Date.parse(session.last_event_at || session.started_at || 0);
  const duration = Math.max(1, (end - start) / 1000);
  const bins = new Map();
  session.traffic.forEach(packet => {
    const bin = Math.floor((Date.parse(packet.at) - start) / 250);
    if (!bins.has(bin)) bins.set(bin, {rx: 0, tx: 0});
    bins.get(bin)[packet.direction] += packet.bytes;
  });
  const maxValue = Math.max(1, ...[...bins.values()].map(bin => bin.rx + bin.tx));
  const yMax = Math.ceil(maxValue / 4) * 4;
  const x = seconds => left + seconds / duration * plotWidth;
  const y = value => top + plotHeight * (1 - value / yMax);
  let content = '';
  for (let index = 0; index <= 4; index++) {
    const value = yMax * index / 4;
    content += `<line x1="${left}" x2="${left + plotWidth}" y1="${y(value)}" y2="${y(value)}" class="grid"/>`;
    content += svgText(left - 10, y(value) + 4, bytes(Math.round(value)), 'end');
  }
  const ticks = width < 450 ? 3 : 5;
  for (let index = 0; index <= ticks; index++) {
    const seconds = duration * index / ticks;
    content += svgText(x(seconds), height - 29, `${seconds.toFixed(duration < 5 ? 1 : 0)}s`, index === 0 ? 'start' : index === ticks ? 'end' : 'middle');
  }
  const barWidth = Math.max(2, Math.min(13, plotWidth / duration * .20));
  bins.forEach((bin, index) => {
    const position = Math.min(left + plotWidth - barWidth, x(index * .25));
    const rxHeight = bin.rx / yMax * plotHeight;
    const txHeight = bin.tx / yMax * plotHeight;
    content += `<g><title>${(index / 4).toFixed(2)}s · from band ${bin.rx} bytes · to band ${bin.tx} bytes</title><rect class="rx" x="${position}" y="${y(bin.rx)}" width="${barWidth}" height="${rxHeight}"/><rect class="tx" x="${position}" y="${y(bin.rx + bin.tx)}" width="${barWidth}" height="${txHeight}"/></g>`;
  });
  content += svgText(left, 13, 'BYTES / 250 MS', 'start');
  content += svgText(left + plotWidth / 2, height - 5, 'Seconds since check started');
  if (!session.traffic.length) content += svgText(left + plotWidth / 2, top + plotHeight / 2, state.running ? 'Waiting for connection traffic' : 'No traffic in this check', 'middle', 'direct-label');
  container.innerHTML = `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="${session.traffic.length} captured stream chunks, ${session.rx_bytes} bytes received and ${session.tx_bytes} bytes sent">${content}</svg>`;
}

function gestureChart(gestures) {
  const container = $('gesture-chart');
  const width = container.clientWidth;
  if (!width) return;
  const height = 260, left = 62, right = 18, top = 25, bottom = 55;
  const plotWidth = Math.max(100, width - left - right), plotHeight = height - top - bottom;
  const start = gestures.length ? gestures[0].press : 0;
  const duration = Math.max(1, ...gestures.map(g => (g.press - start) / 1000)) + 2;
  const maximum = Math.max(1, ...gestures.map(g => g.release - g.press));
  const yMax = Math.ceil(maximum / 50) * 50;
  const x = seconds => left + 8 + seconds / duration * (plotWidth - 16);
  const y = value => top + plotHeight * (1 - value / yMax);
  let content = '';
  for (let index = 0; index <= 3; index++) {
    const value = yMax * index / 3;
    content += `<line x1="${left}" x2="${left + plotWidth}" y1="${y(value)}" y2="${y(value)}" class="grid"/>${svgText(left - 10, y(value) + 4, Math.round(value), 'end')}`;
  }
  gestures.forEach((gesture, index) => {
    const hold = gesture.release - gesture.press, position = x((gesture.press - start) / 1000);
    content += `<g><title>Pinch ${index + 1}: ${preciseClock(gesture.press)} · ${hold} ms</title><rect class="pinch" x="${position - 3}" y="${y(hold)}" width="6" height="${height - bottom - y(hold)}"/>${svgText(position, y(hold) - 8, index + 1, 'middle', 'direct-label')}</g>`;
  });
  const ticks = width < 450 ? 3 : 5;
  for (let i = 0; i <= ticks; i++) content += svgText(x(duration * i / ticks), height - 29, `${(duration * i / ticks).toFixed(0)}s`, i === 0 ? 'start' : i === ticks ? 'end' : 'middle');
  content += svgText(left, 13, 'HOLD DURATION · MS', 'start') + svgText(left + plotWidth / 2, height - 5, 'Seconds after first recorded pinch');
  container.innerHTML = `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="${gestures.length} recorded index pinches with their press-to-release durations">${content}</svg>`;
}

function render() {
  const {device, session, history} = state;
  $('device-name').textContent = device.name;
  const discovery = state.discovery;
  const scanning = state.running && state.mode === 'scan';
  $('scan-band').disabled = state.running || state.external_check;
  $('scan-band').textContent = scanning ? 'Finding…' : 'Find band';
  $('band-choice').disabled = state.running || state.external_check || !discovery.devices.length;
  const optionsKey = JSON.stringify(discovery);
  if (optionsKey !== discoveryOptions) {
    discoveryOptions = optionsKey;
    $('band-choice').replaceChildren(new Option('Choose a band', ''), ...discovery.devices.map(band => new Option(band.name, band.address)));
    $('band-choice').value = discovery.selected || '';
  }
  if (!connectionSetupShown) {
    $('connection-setup').open = !discovery.selected;
    connectionSetupShown = true;
  }
  $('band-discovery-status').textContent = scanning ? 'Looking nearby for 10 seconds…'
    : discovery.scanned && !discovery.devices.length ? 'No band found. Check its charge and pairing mode, disconnect it from the glasses, then try again.'
    : discovery.selected ? `${device.name} selected · press Start to connect`
    : discovery.devices.length ? 'Choose your band above, then press Start.' : 'No band selected yet.';
  $('connection').textContent = scanning ? 'Finding band' : state.phase === 'reading' && state.running ? 'Reading status' : session.connected ? 'Connected' : state.running ? 'Connecting' : 'Disconnected';
  $('connection-detail').textContent = session.connected ? 'Direct Mac → band' : state.running ? 'Check in progress' : 'No active listener';
  $('battery').textContent = device.battery == null ? '—' : `${device.battery}%`;
  $('battery-detail').textContent = device.read_at ? `Read at ${clock(device.read_at)} EDT` : 'Read with a connection check';
  $('firmware').textContent = device.firmware || '—';
  $('verified').textContent = session.verified_packets;
  $('verified-detail').textContent = `${bytes(session.plaintext_bytes)} plaintext bytes · latest check`;
  $('history-count').textContent = history.length;
  $('run-check').disabled = state.running || !state.can_check;
  $('start-session').disabled = state.running || !state.can_check;
  $('stream-mode').disabled = state.running;
  if (state.running && ['dial', 'raw-emg'].includes(state.mode)) $('stream-mode').value = state.mode;
  $('stop-check').hidden = !state.running;
  $('event-state').textContent = state.running ? 'LIVE CHECK' : 'RECORDED';
  $('traffic-source').textContent = session.started_at ? `${state.running ? 'Current' : 'Saved'} check · ${clock(session.started_at)} EDT` : 'Run a check to collect traffic';
  $('traffic-totals').textContent = `RECEIVED ${bytes(session.rx_bytes)} B  /  SENT ${bytes(session.tx_bytes)} B`;
  const deviceErrors = device.read_errors.length ? `Status read: ${device.read_errors.join('; ')}` : null;
  const notice = state.error || (scanning ? 'Finding nearby bands…' : state.external_check ? 'An experiment is recording from the band. Console controls will be available when it finishes.' : state.running ? state.phase === 'reading' ? 'Reading battery and firmware. The direct connection follows automatically.' : session.emg.enabled ? 'Live session active. Receiving directly from the band.' : 'Recording the direct connection.' : deviceErrors || (session.verified_packets ? 'Recording saved. This listener is disconnected.' : 'Ready to connect to the band.'));
  $('notice').textContent = notice;
  $('notice').classList.toggle('error', Boolean(state.error || (!state.running && deviceErrors)));
  const list = $('event-list');
  list.replaceChildren(...session.events.map(event => {
    const li = document.createElement('li'); li.className = event.kind;
    const label = document.createElement('span'); label.textContent = event.label;
    const at = document.createElement('time'); at.dateTime = event.at; at.textContent = preciseClock(event.at);
    li.append(label, at); return li;
  }));
  $('event-empty').hidden = Boolean(session.events.length);
  $('gesture-rows').replaceChildren(...history.map((gesture, index) => {
    const tr = document.createElement('tr');
    [String(index + 1).padStart(2, '0'), preciseClock(gesture.press), preciseClock(gesture.release), `${gesture.release - gesture.press} ms`, preciseClock(gesture.received_at)].forEach(value => {
      const td = document.createElement('td'); td.textContent = value; tr.append(td);
    });
    return tr;
  }));
  $('updated').textContent = `Server reached ${clock(Date.now())} EDT`;
  const emg = session.emg;
  $('emg-state').textContent = emg.enabled ? 'STREAM ACTIVE' : emg.batches ? 'RECORDED' : 'NO SAMPLES';
  $('emg-summary').textContent = emg.config ? `${emg.config.channels} channels · ${bytes(emg.config.sample_rate)} Hz reported · ${bytes(emg.sample_frames)} received sample frames` : 'Sensor configuration not yet received';
  $('emg-detail').textContent = `${bytes(emg.missing_batches)} missing batches detected. Lines break across gaps. ADC interpretation is experimental; voltage conversion and channel placement are unverified.`;
  if (activeTab === 'direct') { emgChart(emg); trafficChart(session); } else gestureChart(history);
}

async function refresh() {
  try {
    const response = await fetch('/api/state');
    if (!response.ok) throw new Error(`Server returned ${response.status}`);
    state = await response.json(); render();
  } catch (error) {
    $('notice').textContent = `Local server unavailable: ${error.message}`;
    $('notice').classList.add('error');
    $('connection').textContent = 'Unknown'; $('connection-detail').textContent = 'Server connection lost';
    $('run-check').disabled = true; $('start-session').disabled = true; $('scan-band').disabled = true; $('band-choice').disabled = true; $('updated').textContent = 'Readings may be stale';
  }
}

async function action(path, body = {}) {
  try {
    const response = await fetch(path, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'A check is already running');
    await refresh();
  } catch (error) { $('notice').textContent = error.message; $('notice').classList.add('error'); }
}
$('run-check').addEventListener('click', () => action('/api/check'));
$('scan-band').addEventListener('click', () => action('/api/scan'));
$('band-choice').addEventListener('change', () => { if ($('band-choice').value) action('/api/select-band', {identifier: $('band-choice').value}); });
$('start-session').addEventListener('click', () => { selectTab('direct'); action('/api/start', {mode: $('stream-mode').value}); });
$('stop-check').addEventListener('click', () => action('/api/stop'));
const tabs = ['direct', 'history'];
function selectTab(name) {
  activeTab = name;
  tabs.forEach(tab => { $(`${tab}-tab`).setAttribute('aria-selected', String(tab === name)); $(`${tab}-panel`).hidden = tab !== name; });
  if (state) render();
}
tabs.forEach((name, index) => {
  $(`${name}-tab`).addEventListener('click', () => selectTab(name));
  $(`${name}-tab`).addEventListener('keydown', event => {
    if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') {
      event.preventDefault(); const next = tabs[1 - index]; selectTab(next); $(`${next}-tab`).focus();
    }
  });
});
new ResizeObserver(() => { if (state) activeTab === 'direct' ? trafficChart(state.session) : gestureChart(state.history); }).observe($('direct-panel'));
new ResizeObserver(() => { if (state && activeTab === 'history') gestureChart(state.history); }).observe($('history-panel'));
refresh();
setInterval(refresh, 1000);
