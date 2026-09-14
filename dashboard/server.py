"""Loopback-only band dashboard with curated data and serialized hardware checks."""

import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import sys
import threading
import time
from urllib.parse import urlparse
from instrumentation.band_access import band_available
from instrumentation.pinch_dial import PinchDial

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CAPTURES = ROOT / "captures"
INSTRUMENTATION = ROOT / "instrumentation"


def read_json(path, default):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


def read_rows(path):
    if path is None:
        return []
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return []
    rows = []
    for line in lines:
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue  # A live writer may not have finished its final JSON line.
    return rows


def session_view(rows, running=False):
    """Allowlist the browser view: raw bytes, keys and certificates never leave here."""
    traffic, events = [], []
    connected, verified, plain_bytes, parameters = False, 0, 0, None
    config, batches, raw_enabled, info_received, recording_start = None, [], False, False, None
    labels = {"connected": "Bluetooth connected", "psm_discovered": "Data channel located",
              "l2cap_open": "Data channel open", "encryption_negotiated": "Fresh session keys negotiated",
              "identity_query_queued": "Certificate query queued", "device_info_query_queued": "Input-service query queued",
              "link_setup_end_queued": "Link setup completed", "config_query_queued": "Sensor configuration requested",
              "disconnected": "Bluetooth disconnected", "stream_ended": "Data channel closed"}
    for row in rows:
        event, at = row.get("event"), row.get("timestamp")
        if event == "connected":
            connected = True
        elif event in ("disconnected", "stream_ended", "probe_error"):
            connected = False
        if event == "encryption_negotiated":
            parameters = row.get("parameters")
        if event == "emg_config_received":
            config = {key: row[key] for key in ("channels", "sample_rate", "adc_bits", "samples_per_batch", "encoding")}
        if event == "emg_batch":
            batches.append({key: row[key] for key in ("timestamp", "sequence", "timestamp_us", "missing_before", "samples")})
        if event == "recording_started":
            recording_start = at
            label = "Live sensor session started"
            events.append({"at": at, "label": label, "kind": "verified"})
        if event == "device_info_received" and row.get("status") == 1:
            info_received = True
            events.append({"at": at, "label": "Input service answered device-info query", "kind": "verified"})
        if event == "stream_control_received" and row.get("status") == 1 and row.get("raw_emg") is not None:
            raw_enabled = bool(row["raw_emg"])
            events.append({"at": at, "label": "Raw EMG enabled" if raw_enabled else "Raw EMG disabled", "kind": "verified"})
        if event == "stream_bytes":
            traffic.append({"at": at, "direction": row["direction"], "bytes": row["count"]})
        elif event == "authenticated_packet":
            count = len(row["plaintext"]) // 2
            verified += 1
            plain_bytes += count
            if verified <= 2 or verified % 100 == 0:
                events.append({"at": at, "label": f"{verified:,} received packets verified", "kind": "verified"})
        elif event in labels:
            events.append({"at": at, "label": labels[event], "kind": "neutral"})
        elif event == "peer_setup":
            events.append({"at": at, "label": row["message"], "kind": "neutral"})
        elif event in ("probe_error", "datax_incomplete"):
            events.append({"at": at, "label": row["message"], "kind": "error"})
    # The process owns the connection; saved logs cannot establish a live one.
    return {"connected": connected and running, "started_at": rows[0].get("timestamp") if rows else None,
            "last_event_at": rows[-1].get("timestamp") if rows else None,
            "verified_packets": verified, "plaintext_bytes": plain_bytes, "parameters": parameters,
            "tx_bytes": sum(p["bytes"] for p in traffic if p["direction"] == "tx"),
            "rx_bytes": sum(p["bytes"] for p in traffic if p["direction"] == "rx"),
            "input_service": info_received,
            "emg": {"config": config, "enabled": raw_enabled and connected and running,
                    "started_at": recording_start or (batches[0]["timestamp"] if batches else None),
                    "batches": len(batches), "sample_frames": len(batches) * 16,
                    "missing_batches": sum(b["missing_before"] for b in batches),
                    "recent": batches[-64:]},
            "traffic": traffic, "events": events[-40:]}


def gesture_history():
    data = read_json(CAPTURES / "coordinated-telemetry-20260913.json", {"transfers": []})
    gestures = []
    for transfer in data["transfers"]:
        selected = {name: sorted([event for event in transfer["events"] if event["action"] == name],
                                  key=lambda event: event["timestamp_ms"])
                    for name in ("INDEX_PRESS", "INDEX_RELEASE", "INDEX_SINGLE_TAP")}
        # This view is for the validated coordinated sample, whose ten sequences
        # each have a following release/tap within 200 ms; reject ambiguous pairs.
        for press, release, tap in zip(*selected.values()):
            p, r, t = (event["timestamp_ms"] for event in (press, release, tap))
            if p < r <= t and t - p < 200:
                gestures.append({"press": p, "release": r, "tap": t,
                                 "received_at": transfer["received_complete"]["timestamp"]})
    return sorted(gestures, key=lambda item: item["press"])


class Dashboard:
    def __init__(self):
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.running = False
        self.mode = "check"
        self.phase = "idle"
        self.error = None
        self.process = None
        self.worker = None
        discovery = read_json(CAPTURES / "mac-band-discovery.json", [])
        self.selection_path = CAPTURES / 'dashboard-selected-band.json'
        selected = read_json(self.selection_path, discovery[0] if discovery else {})
        self.identifier = selected.get('address')
        self.device_name = selected.get('name', 'Meta Neural Band')
        self.devices = []
        self.scanned = False
        saved = sorted(CAPTURES.glob("mac-band-probe-*.jsonl"), key=lambda path: path.stat().st_mtime)
        self.capture = saved[-1] if saved else None
        self.status_path = CAPTURES / "dashboard-band-status.json"
        self.history = gesture_history()
        self.dial_settings_path = CAPTURES / "dashboard-dial-settings.json"
        self.dial_settings = read_json(self.dial_settings_path, {"response": "direct", "sensitivity": 1.})
        self.set_dial_settings(self.dial_settings)

    def set_dial_settings(self, settings):
        if not isinstance(settings, dict) or set(settings) != {"response", "sensitivity"}:
            raise ValueError("Provide response and sensitivity")
        PinchDial(lambda *args, **kwargs: None).configure(**settings)
        with self.lock:
            self.dial_settings = dict(settings)
            temporary = self.dial_settings_path.with_suffix(".tmp")
            temporary.write_text(json.dumps(settings))
            temporary.replace(self.dial_settings_path)

    def state(self):
        with self.lock:
            capture, running, phase, error, mode = self.capture, self.running, self.phase, self.error, self.mode
            discovery = {'devices': list(self.devices), 'scanned': self.scanned, 'selected': self.identifier}
        if not running:
            saved = list(CAPTURES.glob("mac-band-probe-*.jsonl"))
            if saved:
                capture = max(saved, key=lambda path: path.stat().st_mtime)
        status = read_json(self.status_path, {})
        available = band_available()
        return {"running": running, "phase": phase, "mode": mode, "error": error, "can_check": bool(self.identifier) and available,
                "external_check": not running and not available, "discovery": discovery,
                "device": {"name": self.device_name, "battery": status.get("battery"),
                           "firmware": status.get("firmware"), "read_at": status.get("read_at"),
                           "psm": status.get("psm"), "read_errors": status.get("errors", [])},
                "session": session_view(read_rows(capture), running=running and phase == "probing"),
                "history": self.history}

    def interaction(self):
        with self.lock:
            capture, running, mode = self.capture, self.running, self.mode
        data = read_json(capture.with_suffix(".live.json"), {}) if capture else {}
        # A saved pose or a stalled writer must never look like a live hold.
        at = data.get("timestamp")
        age = time.time()-datetime.fromisoformat(at).timestamp() if at else float("inf")
        fresh = 0 <= age < .5
        live = running and mode == "dial" and fresh and data.get("motion_fresh", False)
        view = {k: data[k] for k in ("value", "engaged", "fingers", "rotation", "gesture_count", "steps",
                                   "last_gesture", "reason", "orientation_kind", "timestamp") if k in data}
        view.update(live=live, listening=running and mode == "dial", session=capture.name if capture else None,
                    settings=dict(self.dial_settings), stream_mode=mode if running else None)
        view['recent_gestures'] = [
            {**{k: gesture[k] for k in ('id', 'finger', 'action', 'derived_action', 'synthetic')},
             'age_ms': gesture['age_ms'] + round(age*1000)}
            for gesture in data.get('recent_gestures', [])[-32:]
        ] if live else []
        if not live:
            view.update(engaged=False, fingers={"index": False, "middle": False})
        return view

    def select_device(self, identifier):
        with self.lock:
            if self.running:
                raise ValueError('Stop the current session before choosing a band')
            device = next((device for device in self.devices if device['address'] == identifier), None)
            if device is None:
                raise ValueError('Choose a band from the latest scan')
            selected = {key: device[key] for key in ('address', 'name')}
            temporary = self.selection_path.with_suffix('.tmp')
            temporary.write_text(json.dumps(selected))
            temporary.replace(self.selection_path)
            self.identifier, self.device_name = selected['address'], selected['name']
            self.status_path.write_text('{}')

    def start(self, mode="dial"):
        if mode not in ("check", "dial", "raw-emg", "scan"):
            raise ValueError("Unknown session mode")
        with self.lock:
            if self.running:
                return False
            if mode != 'scan' and not self.identifier:
                raise ValueError("Find and select your band first")
            self.running, self.phase, self.error = True, "scanning" if mode == 'scan' else "reading", None
            self.mode = mode
            self.stop.clear()
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
            if mode != 'scan':
                self.capture = CAPTURES / f"mac-band-probe-dashboard-{stamp}.jsonl"
        self.worker = threading.Thread(target=self._run, args=(mode,), daemon=True)
        self.worker.start()
        return True

    def shutdown(self):
        self.stop.set()
        if self.worker:
            self.worker.join(timeout=6)

    def _child(self, command, timeout):
        # Each Bluetooth subprocess gets a main thread and one hardware owner.
        with open(CAPTURES / "dashboard-worker.log", "a") as log:
            process = subprocess.Popen(command, stdout=log, stderr=log, cwd=ROOT)
            with self.lock:
                self.process = process
            deadline = time.monotonic() + timeout
            try:
                while process.poll() is None:
                    if self.stop.wait(0.1) or time.monotonic() > deadline:
                        process.send_signal(2)
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                        if not self.stop.is_set():
                            raise TimeoutError("The band check timed out.")
                        return process.returncode
                return process.returncode
            finally:
                with self.lock:
                    self.process = None

    def _run(self, mode):
        try:
            if mode == 'scan':
                scan_path = CAPTURES / 'dashboard-scan.json'
                scan_path.unlink(missing_ok=True)
                result = self._child([sys.executable, str(INSTRUMENTATION / 'scan_band.py'), '--output', str(scan_path)], 20)
                if self.stop.is_set():
                    return
                discovery = read_json(scan_path, {})
                if result or 'devices' not in discovery:
                    raise ValueError(discovery.get('error') or 'Bluetooth scan failed. Check Bluetooth access for your terminal in System Settings.')
                with self.lock:
                    self.devices = discovery['devices']
                    self.scanned = True
                return
            self._child([sys.executable, str(INSTRUMENTATION / "read_band_status.py"), self.identifier,
                         "--output", str(self.status_path)], 45)
            if self.stop.is_set():
                return
            with self.lock:
                self.phase = "probing"
            command = [sys.executable, "-u", str(INSTRUMENTATION / "mac_band_probe.py"), self.identifier,
                       "--seconds", "300" if mode == "dial" else "60" if mode == "raw-emg" else "30", "--end-link-setup", "--query-device-info",
                       "--output", str(self.capture)]
            if mode != "check":
                command += ["--stream-control", mode]
            if mode == "dial":
                command += ["--dial-settings", str(self.dial_settings_path)]
            result = self._child(command, 340 if mode == "dial" else 100 if mode == "raw-emg" else 40)
            if result:
                with self.lock:
                    self.error = "The encrypted check did not complete. See session events."
        except (OSError, ValueError, TimeoutError) as error:
            with self.lock:
                self.error = str(error)
        finally:
            with self.lock:
                self.phase = "stopped" if self.stop.is_set() else "complete"
                self.running = False


def make_handler(dashboard):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def allowed_host(self):
            return self.headers.get("Host") in (f"localhost:{self.server.server_port}", f"127.0.0.1:{self.server.server_port}")

        def respond(self, status, body, content_type="application/json"):
            if isinstance(body, dict):
                body = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if not self.allowed_host():
                return self.respond(403, {"error": "Localhost only"})
            route = urlparse(self.path).path
            if route == "/api/state":
                return self.respond(200, dashboard.state())
            if route == "/api/interaction":
                return self.respond(200, dashboard.interaction())
            assets = {"/": ("index.html", "text/html; charset=utf-8"),
                      "/dashboard.js": ("dashboard.js", "text/javascript; charset=utf-8"),
                      "/hand.js": ("hand.js", "text/javascript; charset=utf-8"),
                      "/hand-model.js": ("hand-model.js", "text/javascript; charset=utf-8"),
                      "/gesture-animation.js": ("gesture-animation.js", "text/javascript; charset=utf-8"),
                      "/models/right-hand.glb": ("models/right-hand.glb", "model/gltf-binary"),
                      "/vendor/GLTFLoader.js": ("vendor/GLTFLoader.js", "text/javascript; charset=utf-8"),
                      "/vendor/BufferGeometryUtils.js": ("vendor/BufferGeometryUtils.js", "text/javascript; charset=utf-8"),
                      "/vendor/SkeletonUtils.js": ("vendor/SkeletonUtils.js", "text/javascript; charset=utf-8"),
                      "/vendor/three.module.js": ("vendor/three.module.js", "text/javascript; charset=utf-8"),
                      "/vendor/three.core.js": ("vendor/three.core.js", "text/javascript; charset=utf-8"),
                      "/dashboard.css": ("dashboard.css", "text/css; charset=utf-8")}
            if route not in assets:
                return self.respond(404, {"error": "Not found"})
            name, content_type = assets[route]
            self.respond(200, (HERE / "static" / name).read_bytes(), content_type)

        def do_POST(self):
            origin = self.headers.get("Origin")
            if not self.allowed_host() or origin not in (None, f"http://{self.headers.get('Host')}"):
                return self.respond(403, {"error": "Same-origin localhost requests only"})
            if self.headers.get("Content-Type") != "application/json":
                return self.respond(415, {"error": "JSON required"})
            if self.path in ("/api/dial-settings", "/api/select-band", "/api/start"):
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    if not 0 < size <= 128:
                        raise ValueError("Invalid settings length")
                    settings = json.loads(self.rfile.read(size))
                    if self.path == '/api/start':
                        if not isinstance(settings, dict) or set(settings) != {'mode'} or settings['mode'] not in ('dial', 'raw-emg'):
                            raise ValueError('Choose hand + dial or sEMG')
                        started = dashboard.start(settings['mode'])
                        return self.respond(202 if started else 409, {'started': started})
                    if self.path == '/api/select-band':
                        if not isinstance(settings, dict) or set(settings) != {'identifier'}:
                            raise ValueError('Provide a band identifier')
                        dashboard.select_device(settings['identifier'])
                        return self.respond(200, {'selected': dashboard.identifier})
                    dashboard.set_dial_settings(settings)
                    return self.respond(200, {"settings": dashboard.dial_settings})
                except (ValueError, TypeError) as error:
                    return self.respond(400, {"error": str(error)})
            if self.headers.get("Content-Length", "0") not in ("0", "2"):
                return self.respond(400, {"error": "This action takes no arguments"})
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if self.path in ("/api/check", "/api/scan"):
                try:
                    started = dashboard.start(mode={"/api/check": "check", "/api/scan": "scan"}[self.path])
                    self.respond(202 if started else 409, {"started": started})
                except ValueError as error:
                    self.respond(400, {"error": str(error)})
            elif self.path == "/api/stop":
                dashboard.stop.set()
                self.respond(202, {"stopping": True})
            else:
                self.respond(404, {"error": "Not found"})
    return Handler


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    CAPTURES.mkdir(exist_ok=True)
    dashboard = Dashboard()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(dashboard))
    print(f"Local dashboard: http://localhost:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        dashboard.stop.set()
    finally:
        server.server_close()
        dashboard.shutdown()
