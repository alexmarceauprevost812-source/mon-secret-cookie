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

    def test_asset_id_stable_across_modes(self):
        mac='AA:BB:CC:DD:EE:FF'
        self.assertEqual(network.asset_id(mac=mac),network.asset_id(mac=mac.lower()))
        self.assertIsNone(network.asset_id())
        host=network._annotate_host({'addresses':[{'addr':'10.0.0.5','addrtype':'ipv4'},{'addr':mac,'addrtype':'mac'}]})
        linux=network._annotate_neighbor({'dst':'10.0.0.5','lladdr':mac})
        windows=network._annotate_neighbor({'IPAddress':'10.0.0.5','LinkLayerAddress':mac})
        self.assertTrue(host['asset_id'].startswith('DEV-'))
        self.assertEqual(host['asset_id'],linux['asset_id'])
        self.assertEqual(host['asset_id'],windows['asset_id'])

    def test_devices_active_requires_authorization(self):
        # L'annotation ne contourne pas le gate : sans --authorized, refus.
        with self.assertRaises(core.AuditError): network.devices('192.168.1.0/24',False)

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

    def test_bilan_label(self):
        from mon_secret_cookie import audit
        failing=audit.AuditError('indisponible')
        patches=[patch(f'mon_secret_cookie.network.{name}',side_effect=failing)
                 for name in ('local_addresses','ports','wifi_info','scan_local','devices')]
        with contextlib.ExitStack() as stack:
            for p in patches: stack.enter_context(p)
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            out=io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(main(['bilan','--label','pc-bureau']),0)
            self.assertIn('Appareil : pc-bureau',out.getvalue())
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(['bilan','--label','bad/;name']),1)

    def test_bilan_no_neighbors(self):
        from mon_secret_cookie import audit
        titles=[s['titre'] for s in audit.collect(include_neighbors=False)['sections']]
        self.assertFalse(any('Voisins' in t for t in titles))
        self.assertTrue(any('Voisins' in s['titre'] for s in audit.collect()['sections']))

    def test_record_survives_disk_full(self):
        import errno
        enospc=OSError(errno.ENOSPC,'No space left on device')
        self.assertTrue(core.disk_full_hint(enospc))
        self.assertIsNone(core.disk_full_hint(OSError(errno.EACCES,'perm')))
        with patch('mon_secret_cookie.core.private_write',side_effect=enospc), \
             contextlib.redirect_stderr(io.StringIO()) as err:
            result=core.record('device-id',{'device_id':'MSC-X'})
        self.assertEqual(result,{'device_id':'MSC-X'})
        self.assertIn('Disque plein',err.getvalue())

    def test_command_output_despite_failed_audit(self):
        import errno
        enospc=OSError(errno.ENOSPC,'No space left on device')
        with patch('mon_secret_cookie.network.ports',return_value={'listeners':[]}), \
             patch('mon_secret_cookie.core.private_write',side_effect=enospc), \
             contextlib.redirect_stdout(io.StringIO()) as out, \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['ports']),0)
        self.assertIn('listeners',out.getvalue())

    def test_cookies_tagged_with_device_id(self):
        p=self.base/'cookies.txt'; p.write_text(cookies.DEMO)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(main(['cookies','--file',str(p)]),0)
        data=json.loads(out.getvalue())
        self.assertEqual(data['device_id'],core.device_id()['device_id'])
        self.assertIn('cookies',data)
        # Vérification d'ID : un ID erroné refuse la commande.
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['cookies','--file',str(p),'--device-id','MSC-FAUX']),1)

    def test_record_cleans_partial_audit_file(self):
        import errno
        def partial_then_fail(path, text):
            Path(path).write_text('')
            raise OSError(errno.ENOSPC,'No space left on device')
        with patch('mon_secret_cookie.core.private_write',side_effect=partial_then_fail), \
             contextlib.redirect_stderr(io.StringIO()):
            core.record('ports',{'listeners':[]})
        self.assertEqual(list((self.base/'state').glob('*.json')),[])

    def test_report_skips_corrupt_audit_file(self):
        sd=core.state_dir()
        core.private_write(sd/'aaa.json',json.dumps({'command':'ports','time':'t','result':{}}))
        (sd/'bbb.json').write_text('')
        out=self.base/'r.txt'
        self.assertEqual(core.report(out,'txt')['audits'],1)

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
