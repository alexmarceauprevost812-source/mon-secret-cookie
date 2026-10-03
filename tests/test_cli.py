import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from mon_secret_cookie import core, cookies, network
from mon_secret_cookie.cli import main
from mon_secret_cookie.lab import create_app

class Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name)
        self.env=patch.dict(os.environ,{'MSC_STATE_DIR':str(self.base/'state')})
        self.env.start(); self.addCleanup(self.env.stop)

    def test_id_persistent_private(self):
        self.assertEqual(core.device_id(),core.device_id())
        self.assertEqual((self.base/'state/device-id').stat().st_mode & 0o777,0o600)

    def test_cookie_redaction_http_only(self):
        p=self.base/'cookies.txt'; p.write_text(cookies.DEMO)
        result=cookies.analyze(p)
        self.assertTrue(result['cookies'][0]['http_only'])
        self.assertNotIn('FICTIF',json.dumps(result))
        self.assertEqual(len(result['cookies']),2)

    def test_cookie_symlink_refused(self):
        p=self.base/'original';p.write_text(cookies.DEMO)
        s=self.base/'cookies.txt';s.symlink_to(p)
        with self.assertRaises(core.AuditError): cookies.analyze(s)

    def test_non_regular_refused(self):
        p=self.base/'fifo';os.mkfifo(p)
        with self.assertRaises(core.AuditError): core.owned_text(p)

    def test_external_scan_authorization_and_injection(self):
        with patch('mon_secret_cookie.network.run') as run:
            for targets,authorized in [(['127.0.0.1'],False),(['--script=evil'],True),(['224.0.0.1'],True)]:
                with self.assertRaises((ValueError,core.AuditError)):
                    network.authorized_scan(targets,authorized)
            run.assert_not_called()

    def test_lan_scope(self):
        with patch('mon_secret_cookie.network.interfaces',return_value=[{'ifname':'eth0','operstate':'UP','addr_info':[{'family':'inet','local':'192.168.1.2','prefixlen':24}]}]):
            for cidr in ['192.168.2.0/24','192.168.0.0/16','8.8.8.0/24']:
                with self.assertRaises(core.AuditError): network.devices(cidr,True)

    def test_wifite_status_no_execution(self):
        with patch('shutil.which',return_value='/usr/bin/wifite'), patch('mon_secret_cookie.network.run') as run:
            self.assertTrue(network.wifite_info()['installed'])
            run.assert_not_called()

    def test_ports_service(self):
        with patch('mon_secret_cookie.network.run',return_value='tcp LISTEN 0 128 127.0.0.1:80 0.0.0.0:*\n'):
            result=network.ports()['listeners'][0]
            self.assertEqual(result['port'],80)
            self.assertEqual(result['service'],'http')

    def test_invalid_nmap_xml(self):
        with self.assertRaises(core.AuditError): network.parse_nmap('invalid')

    def test_nmap_ipv6_and_fixed_flags(self):
        xml='<nmaprun><host><status state="up"/><address addr="::1" addrtype="ipv6"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>'
        with patch('mon_secret_cookie.network.run',return_value=xml) as run:
            result=network.scan_address('::1')
            self.assertEqual(result[0]['ports'][0]['service'],'http')
            self.assertIn('-6',run.call_args.args[0])
            self.assertNotIn('-sV',run.call_args.args[0])

    def test_report_no_overwrite(self):
        core.record('device-id',core.device_id())
        for fmt in ['txt','json']:
            p=self.base/('report.'+fmt)
            self.assertEqual(core.report(p,fmt)['audits'],1)
            with self.assertRaises(FileExistsError): core.report(p,fmt)

    def test_cli_errors(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['nmap','127.0.0.1']),1)
            self.assertEqual(main(['flask-lab','--port','80']),1)

    def test_local_device_id_mismatch(self):
        with patch('mon_secret_cookie.network.scan_local') as scan, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['scan-local','--device-id','MSC-INCORRECT']),1)
            scan.assert_not_called()

    def test_local_device_id_match(self):
        device=core.device_id()['device_id']
        with patch('mon_secret_cookie.network.scan_local',return_value={'hosts':[]}), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(['scan-local','--device-id',device]),0)
            self.assertEqual(json.loads(output.getvalue())['device_id'],device)

    def test_bilan_text_best_effort(self):
        from mon_secret_cookie import audit
        failing=audit.AuditError('indisponible')
        with patch('mon_secret_cookie.network.local_addresses',side_effect=failing), \
             patch('mon_secret_cookie.network.ports',side_effect=failing), \
             patch('mon_secret_cookie.network.wifi_info',side_effect=failing), \
             patch('mon_secret_cookie.network.scan_local',side_effect=failing), \
             patch('mon_secret_cookie.network.devices',side_effect=failing), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(['bilan']),0)
        text=output.getvalue()
        self.assertIn('Bilan défensif',text)
        self.assertIn('device_id',text)
        self.assertIn('Indisponible',text)

    def test_bilan_no_neighbors(self):
        from mon_secret_cookie import audit
        titles=[s['titre'] for s in audit.collect(include_neighbors=False)['sections']]
        self.assertFalse(any('Voisins' in t for t in titles))
        self.assertTrue(any('Voisins' in s['titre'] for s in audit.collect()['sections']))

    def test_flask_cookie_and_host(self):
        app=create_app();app.testing=True
        c=app.test_client()
        self.assertEqual(c.get('/').status_code,200)
        response=c.post('/set')
        header=response.headers['Set-Cookie']
        self.assertIn('HttpOnly',header);self.assertIn('SameSite=Strict',header)
        self.assertNotIn('FICTIF',c.get('/').get_data(as_text=True))
        c.post('/clear')
        self.assertIn('absent',c.get('/').get_data(as_text=True))
        self.assertEqual(c.get('/',headers={'Host':'attacker.example'}).status_code,400)

if __name__=='__main__': unittest.main()
