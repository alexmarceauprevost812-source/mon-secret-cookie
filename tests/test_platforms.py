import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from mon_secret_cookie import core, network, platforms
from mon_secret_cookie.cli import main


class PlatformTests(unittest.TestCase):
    def test_windows_interfaces_feed_authorized_lan_validation(self):
        rows=[{'InterfaceAlias':'Wi-Fi','IPAddress':'192.168.1.12','PrefixLength':24,'InterfaceIndex':7}]
        with patch.object(platforms,'ps_rows',side_effect=[rows,[{'InterfaceIndex':7}]]):
            interfaces=platforms.windows_interfaces()
        self.assertEqual(interfaces[0]['operstate'],'UP')
        with patch.object(network,'interfaces',return_value=interfaces), patch.object(network,'run',return_value='<nmaprun/>') as run:
            network.devices('192.168.1.0/24',True)
            self.assertIn('-sn',run.call_args.args[0])
            with self.assertRaises(core.AuditError): network.devices('192.168.2.0/24',True)

    def test_windows_tcp_udp_ports(self):
        with patch.object(platforms,'ps_rows',side_effect=[[{'LocalAddress':'127.0.0.1','LocalPort':5000}],[{'LocalAddress':'::','LocalPort':53}]]):
            result=platforms.windows_ports()['listeners']
        self.assertEqual([p['protocol'] for p in result],['tcp','udp'])
        self.assertEqual(result[0]['port'],5000)

    def test_windows_wifi_never_requests_keys(self):
        with patch.object(platforms,'is_windows',return_value=True), patch.object(network,'run',return_value='SSID: Lab') as run:
            result=network.wifi_info()
        self.assertEqual(run.call_args.args[0],['netsh','wlan','show','interfaces'])
        self.assertIn('Lab',result['interfaces'])

    def test_termux_wifi_filters_unknown_fields(self):
        with patch.object(platforms,'is_windows',return_value=False), patch.object(platforms,'is_termux',return_value=True), patch.object(network,'run',return_value=json.dumps({'ssid':'Lab','bssid':'aa:bb','password':'SECRET','other':'secret'})):
            result=network.wifi_info()
        self.assertEqual(result['connection'],{'ssid':'Lab','bssid':'aa:bb'})

    def test_termux_local_fallback_reports_scope(self):
        with patch.object(platforms,'is_termux',return_value=True), patch.object(network,'interfaces',side_effect=core.AuditError('Permission denied')), patch.object(network,'scan_address',return_value=[]) as scan:
            result=network.scan_local()
        self.assertEqual(result['addresses'],['127.0.0.1','::1'])
        self.assertIn('localhost',result['limitation'])
        self.assertEqual(scan.call_count,2)

    def test_termux_blocked_interfaces_cannot_enable_lan_scan(self):
        with patch.object(network,'interfaces',side_effect=core.AuditError('Permission denied')), patch.object(network,'run') as run:
            with self.assertRaises(core.AuditError): network.devices('192.168.1.0/24',True)
            run.assert_not_called()

    def test_windows_foreign_owner_file_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'cookies.txt';path.write_text('private')
            with patch.object(platforms,'is_windows',return_value=True), patch.object(platforms,'windows_owner',return_value=False):
                with self.assertRaises(core.AuditError): core.owned_text(path)

    def test_device_id_works_without_termux_network_permissions(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ,{'MSC_STATE_DIR':directory}), patch.object(platforms,'is_termux',return_value=True), patch.object(network,'interfaces',side_effect=core.AuditError('Permission denied')), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(['device-id']),0)
            result=json.loads(output.getvalue())
            self.assertTrue(result['device_id'].startswith('MSC-'))
            self.assertEqual(result['interfaces'],[])
            self.assertIn('Android',result['limitation'])

if __name__=='__main__': unittest.main()
