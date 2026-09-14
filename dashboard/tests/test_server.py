"""Curated live views must never expose stale holds or raw capture secrets."""

from datetime import datetime, timedelta, timezone
import json
from http.client import HTTPConnection
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from dashboard import server as dashboard_server


class DashboardTests(unittest.TestCase):
    def test_saved_or_stalled_pose_is_not_live_and_secrets_are_excluded(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(dashboard_server,'CAPTURES',Path(directory)):
            dashboard = dashboard_server.Dashboard()
            dashboard.capture = Path(directory)/'test.jsonl'
            sidecar = dashboard.capture.with_suffix('.live.json')
            row = {'timestamp':datetime.now(timezone.utc).isoformat(),'value':61,'engaged':True,
                   'fingers':{'index':True,'middle':False},'motion_fresh':True,'rotation':[1,0,0,0],
                   'recent_gestures':[{'id':1,'finger':'thumb','action':'up','derived_action':'unknown',
                                       'synthetic':False,'age_ms':12,'plaintext':'private'}],
                   'plaintext':'sensitive','shared_secret':'secret'}
            sidecar.write_text(json.dumps(row))
            self.assertFalse(dashboard.interaction()['live'])
            dashboard.running=True
            dashboard.mode='dial'
            self.assertTrue(dashboard.interaction()['engaged'])
            self.assertTrue(dashboard.interaction()['live'])
            gesture = dashboard.interaction()['recent_gestures'][0]
            self.assertEqual((gesture['finger'], gesture['action']), ('thumb', 'up'))
            self.assertNotIn('plaintext', gesture)
            row['timestamp']=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
            sidecar.write_text(json.dumps(row))
            view=dashboard.interaction()
            self.assertEqual(view['value'],61)
            self.assertFalse(view['live'])
            self.assertFalse(view['engaged'])
            self.assertEqual(view['fingers'],{'index':False,'middle':False})
            self.assertNotIn('plaintext',view)
            self.assertNotIn('shared_secret',view)
            self.assertEqual(view['recent_gestures'], [])

    def test_find_choose_and_start_through_http_without_saved_discovery(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(dashboard_server, 'CAPTURES', Path(directory)):
            dashboard = dashboard_server.Dashboard()
            band = {'address':'33AC4613-56C1-CDC7-987A-5DA9BF0D7035', 'name':'Meta Band 00BC', 'rssi':-48}
            commands = []

            def hardware(command, timeout):
                commands.append(command)
                if any(item.endswith('scan_band.py') for item in command):
                    Path(command[-1]).write_text(json.dumps({'devices':[band], 'error':None}))
                return 0

            server = dashboard_server.ThreadingHTTPServer(('127.0.0.1', 0), dashboard_server.make_handler(dashboard))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            def request(path, body=None):
                connection = HTTPConnection('127.0.0.1', server.server_port, timeout=2)
                connection.request('GET' if body is None else 'POST', path,
                                   None if body is None else json.dumps(body), {'Content-Type':'application/json'})
                response = connection.getresponse()
                result = response.status, json.loads(response.read())
                connection.close()
                return result

            def settle():
                deadline = time.monotonic()+2
                while dashboard.running and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertFalse(dashboard.running)

            try:
                with patch.object(dashboard, '_child', side_effect=hardware):
                    self.assertEqual(request('/api/start', {'mode':'dial'})[0], 400)
                    self.assertEqual(request('/api/scan', {})[0], 202)
                    settle()
                    self.assertEqual(request('/api/state')[1]['discovery']['devices'], [band])
                    self.assertEqual(request('/api/select-band', {'identifier':'not-discovered'})[0], 400)
                    self.assertEqual(request('/api/select-band', {'identifier':band['address']})[0], 200)
                    self.assertEqual(dashboard_server.Dashboard().identifier, band['address'])
                    self.assertEqual(request('/api/start', {'mode':'dial'})[0], 202)
                    settle()
                    probe = commands[-1]
                    self.assertIn(band['address'], probe)
                    self.assertEqual(probe[probe.index('--stream-control')+1], 'dial')
                    self.assertIn('--dial-settings', probe)
                    self.assertIsNone(request('/api/state')[1]['error'])
                    self.assertEqual(request('/api/start', {'mode':'raw-emg'})[0], 202)
                    settle()
                    probe = commands[-1]
                    self.assertEqual(probe[probe.index('--stream-control')+1], 'raw-emg')
                    self.assertEqual(probe[probe.index('--seconds')+1], '60')
                    self.assertNotIn('--dial-settings', probe)
                    dashboard.running = True
                    self.assertEqual(request('/api/select-band', {'identifier':band['address']})[0], 400)
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_dial_settings_are_validated_and_saved_for_the_receiver(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(dashboard_server,'CAPTURES',Path(directory)):
            dashboard=dashboard_server.Dashboard()
            dashboard.set_dial_settings({'response':'rate','sensitivity':2.5})
            self.assertEqual(json.loads(dashboard.dial_settings_path.read_text()),{'response':'rate','sensitivity':2.5})
            for invalid in [{'response':'other','sensitivity':2}, {'response':'direct','sensitivity':100}, {'response':'direct'}]:
                with self.assertRaises(ValueError):
                    dashboard.set_dial_settings(invalid)
            self.assertEqual(dashboard.interaction()['settings'],{'response':'rate','sensitivity':2.5})


if __name__ == '__main__':
    unittest.main()
