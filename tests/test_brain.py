import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from mon_secret_cookie import ai_planner, brain, cookie_inventory, core, fusion, notifications, programmer, security


def draft(tool='report', targets=None):
    return {'tasks': [{'id': 'T1', 'tool': tool, 'target_ids': targets or []}]}


class BrainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for context in [patch.dict(os.environ, MSC_STATE_DIR=str(self.root/'state'), MSC_NOTIFICATIONS='0'),
                        patch.object(fusion, 'executable', return_value='/usr/bin/tool'),
                        patch.object(fusion, 'storage', return_value={'scan_allowed': True})]:
            context.start(); self.addCleanup(context.stop)

    def target(self):
        return security.add_target('lab', 'responsable', '192.168.1.0/24', ['inventory'],
            (datetime.now(timezone.utc)+timedelta(days=1)).isoformat(), 'preuve test')

    def plan(self, ids=None, proposal=None):
        with patch.object(ai_planner, 'local_plan', return_value=proposal or draft()):
            return brain.create('Vérifier mon laboratoire', ids, model='test-local')

    def test_plan_memory_and_preview_no_execution(self):
        plan = self.plan()
        self.assertEqual(brain.plans(plan['id'])['objective'], plan['objective'])
        with patch.object(brain, 'run_task') as runner:
            self.assertFalse(brain.resume(plan['id'])['network_executed'])
            runner.assert_not_called()

    def test_empty_memory_does_not_create_database(self):
        self.assertEqual(brain.plans(), {'plans': []})
        self.assertEqual(programmer.status()['remaining'], 250)
        self.assertFalse((self.root/'state').exists())

    def test_inventory_inserted_for_all_selected_targets(self):
        target = self.target(); plan = self.plan([target['id']])
        self.assertEqual(plan['tasks'][0]['tool'], 'inventory')
        self.assertEqual(plan['tasks'][0]['target_ids'], [target['id']])
        self.assertFalse(plan['schedule']['enabled'])

    def test_model_cannot_select_other_target_or_shell(self):
        for proposal in (draft('shell'), draft('inventory', ['AUTH-foreign']),
                         {'tasks': [{'id': 'T1', 'tool': 'report', 'target_ids': [], 'command': 'anything'}]},
                         draft('project_tests')):
            with self.assertRaises(core.AuditError):
                self.plan(proposal=proposal)
        self.assertEqual(brain.plans(), {'plans': []})

    def test_revoked_authorization_blocks_model_and_resume(self):
        target = self.target(); plan = self.plan([target['id']]); security.revoke(target['id'])
        with patch.object(ai_planner, 'local_plan') as model, self.assertRaises(core.AuditError):
            brain.create('test', [target['id']], model='test')
        model.assert_not_called()
        with patch.object(brain, 'run_task') as runner, self.assertRaises(core.AuditError):
            brain.resume(plan['id'], True)
        runner.assert_not_called()
        self.assertEqual(brain.plans(plan['id'])['status'], 'blocked')

    def test_resume_skips_completed_steps_and_records_attempts(self):
        proposal = {'tasks': [{'id': 'one', 'tool': 'report', 'target_ids': []},
                              {'id': 'two', 'tool': 'diagnostic_host', 'target_ids': []}]}
        plan = self.plan(proposal=proposal)
        with patch.object(brain, 'run_task', side_effect=[{'validated': True}, core.AuditError('interruption')]):
            with self.assertRaises(core.AuditError):
                brain.resume(plan['id'], True)
        with patch.object(brain, 'run_task', return_value={'validated': True}) as runner:
            finished = brain.resume(plan['id'], True)
        self.assertEqual(runner.call_count, 1)
        self.assertEqual(finished['status'], 'completed')
        self.assertEqual([t['attempts'] for t in finished['tasks']], [1, 2])

    def test_unvalidated_result_is_failed(self):
        plan = self.plan()
        with patch.object(brain, 'run_task', return_value={'validated': False}), self.assertRaises(core.AuditError):
            brain.resume(plan['id'], True)
        self.assertEqual(brain.plans(plan['id'])['status'], 'failed')

    def test_no_overlapping_execution(self):
        plan = self.plan()
        with brain.lock(), patch.object(brain, 'run_task') as runner:
            with self.assertRaises(core.AuditError):
                brain.resume(plan['id'], True)
        runner.assert_not_called()

    def test_watch_waits_60_seconds_after_completion_and_restarts(self):
        target = self.target(); plan = self.plan([target['id']])
        clock = [1000.0]; starts = []
        def run(task, plan):
            if task['tool'] == 'inventory':
                starts.append(clock[0]); clock[0] += 5
            return {'validated': True}
        def sleep(seconds): clock[0] += seconds
        with patch.object(brain, 'run_task', side_effect=run):
            first = brain.watch(plan['id'], True, 2, lambda: clock[0], sleep)
            self.assertEqual(starts, [1000.0, 1065.0])
            self.assertFalse(first['schedule']['enabled'])
            again = brain.watch(plan['id'], True, 1, lambda: clock[0], sleep)
        self.assertEqual(starts[-1], 1130.0)
        self.assertEqual(again['cycle'], 3)

    def test_watch_no_target_or_no_execution_never_runs(self):
        plan = self.plan()
        with self.assertRaises(core.AuditError):
            brain.watch(plan['id'], True, 1)
        target = self.target(); plan = self.plan([target['id']])
        with patch.object(brain, 'run_task') as runner:
            self.assertFalse(brain.watch(plan['id'])['enabled'])
        runner.assert_not_called()

    def test_inventory_reuses_existing_engine_and_new_asset_comparison(self):
        result = {'status': 'completed', 'id': 'RUN-test', 'pending': [],
                  'inventories': [{'changes': {'new': [{'asset_id': 'DEV-test'}]}}]}
        with patch.object(fusion, 'scan', return_value=result) as scan:
            report = brain.run_task({'tool': 'inventory', 'target_ids': ['AUTH-test']})
        scan.assert_called_once_with(['AUTH-test'], True)
        self.assertEqual(report['new_assets'], 1)

    def test_existing_authorizations_are_not_changed(self):
        target = self.target(); before = security.targets()
        self.plan([target['id']])
        self.assertEqual(security.targets(), before)

    def test_history_keeps_failure_proof_after_successful_resume(self):
        plan = self.plan()
        with patch.object(brain, 'run_task', side_effect=core.AuditError('preuve interruption')):
            with self.assertRaises(core.AuditError): brain.resume(plan['id'], True)
        with patch.object(brain, 'run_task', return_value={'validated': True}):
            brain.resume(plan['id'], True)
        events = brain.history(plan['id'])['events']
        self.assertTrue(any(e['tasks'][0]['error'] == 'preuve interruption' for e in events))
        self.assertEqual(events[-1]['status'], 'completed')

    def test_watch_revocation_during_wait_stops_next_inventory(self):
        target = self.target(); plan = self.plan([target['id']]); clock = [0.0]; revoked = [False]
        def sleep(seconds):
            clock[0] += seconds
            if not revoked[0]:
                security.revoke(target['id']); revoked[0] = True
        with patch.object(brain, 'run_task', return_value={'validated': True}) as runner:
            with self.assertRaises(core.AuditError):
                brain.watch(plan['id'], True, 2, lambda: clock[0], sleep)
        self.assertEqual(runner.call_count, len(plan['tasks']))
        result = brain.plans(plan['id'])
        self.assertEqual(result['status'], 'blocked')
        self.assertFalse(result['schedule']['enabled'])

    def test_budget_stops_process_before_251_and_reports_attempts(self):
        for _ in range(249): programmer.reserve('fixed-tool')
        with patch.object(core, 'run', return_value='ok') as run:
            with programmer.execution_budget():
                self.assertEqual(core.run(['fixed-tool']), 'ok')
                with self.assertRaises(core.AuditError): core.run(['fixed-tool'])
        self.assertEqual(run.call_count, 1)
        self.assertEqual(programmer.report()['budget']['used'], 250)
        self.assertTrue(programmer.report()['events'])

    def test_mission_cli_delegates_to_plan_resume(self):
        with patch.object(brain, 'resume', return_value={'mode': 'preview'}) as resume, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(fusion.main(['mission', '--plan-id', 'PLN-test']), 0)
        resume.assert_called_once_with('PLN-test', False)

    def test_new_assets_and_cookie_metadata_combined_without_remote_file_access(self):
        folder = self.root/'selected'; folder.mkdir()
        (folder/'cookies.txt').write_text('example.test\tFALSE\t/\tTRUE\t0\tname\tSECRET\n')
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(fusion.main(['nouvelles', '--cookies-dossier', str(folder)]), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result['new'], [])
        self.assertEqual(len(result['local_cookie_files']['new_files']), 1)
        self.assertNotIn('SECRET', output.getvalue())

    def test_budget_250_persisted_251st_refused_once_notified(self):
        for _ in range(250): programmer.reserve('fixed-tool')
        self.assertEqual(programmer.status()['remaining'], 0)
        with patch.object(notifications, 'required') as notice:
            for _ in range(2):
                with self.assertRaises(core.AuditError): programmer.reserve('fixed-tool')
        notice.assert_called_once_with('renewal')
        self.assertEqual(programmer.status()['used'], 250)

    def test_budget_wrapper_counts_and_restores_existing_functions(self):
        with patch.object(fusion, 'version_probe', return_value={'status': 'ok'}) as probe:
            original = fusion.version_probe
            with programmer.execution_budget():
                fusion.version_probe(['fixed-tool', '--version'])
            self.assertIs(fusion.version_probe, original)
        probe.assert_called_once()
        self.assertEqual(programmer.status()['used'], 1)

    def test_sudo_renew_requires_terminal_and_never_captures_password(self):
        with patch.object(programmer.sys.stdin, 'isatty', return_value=False), self.assertRaises(core.AuditError):
            programmer.renew()
        programmer.reserve('fixed-tool')
        with patch.object(programmer.sys.stdin, 'isatty', return_value=True), patch.object(programmer.sys.stderr, 'isatty', return_value=True), patch.object(programmer.Path, 'is_file', return_value=True), patch.object(programmer.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run, contextlib.redirect_stdout(io.StringIO()):
            result = programmer.renew()
        run.assert_called_once_with(['/usr/bin/sudo', '-k', '-v'])
        self.assertEqual(result['remaining'], 250)
        self.assertEqual(result['generation'], 2)

    def test_failed_sudo_preserves_count(self):
        programmer.reserve('fixed-tool')
        with patch.object(programmer.sys.stdin, 'isatty', return_value=True), patch.object(programmer.sys.stderr, 'isatty', return_value=True), patch.object(programmer.Path, 'is_file', return_value=True), patch.object(programmer.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(core.AuditError):
            programmer.renew()
        self.assertEqual(programmer.status()['used'], 1)

    def test_cookie_metadata_new_changed_and_no_values(self):
        folder = self.root/'selected'; folder.mkdir()
        file = folder/'cookies.txt'
        file.write_text('example.test\tFALSE\t/\tTRUE\t0\tsession\tSECRET_VALUE_NOT_TO_STORE\n')
        report = cookie_inventory.collect(folder)
        self.assertEqual(len(report['new_files']), 1)
        self.assertNotIn('SECRET_VALUE_NOT_TO_STORE', json.dumps(report))
        self.assertEqual(cookie_inventory.collect(folder)['new_files'], [])
        file.write_text('example.test\tFALSE\t/\tFALSE\t0\tsession\tSECRET_NEW_VALUE\n')
        self.assertEqual(len(cookie_inventory.collect(folder)['changed_files']), 1)
        with security.database() as conn:
            stored = conn.execute('SELECT data FROM cookie_inventory').fetchone()['data']
        self.assertNotIn('SECRET_', stored)


class ConnectorTests(unittest.TestCase):
    def test_invalid_local_catalogue_does_not_crash(self):
        with patch.object(ai_planner, 'local_request', return_value=None):
            self.assertTrue(all(s['status'] == 'unavailable' for s in ai_planner.local_models()))
    def test_local_catalogue_excludes_cloud_and_no_model_download(self):
        data = {'models': [{'name': 'local:latest'}, {'name': 'remote:cloud'}, {'name': 'alias', 'remote_host': 'remote'}]}
        with patch.object(ai_planner, 'local_request', return_value=data):
            result = ai_planner.local_models()
        self.assertEqual(result[0]['models'], ['local:latest'])

    def test_local_plan_structured_request_and_tools_refused(self):
        with patch.object(ai_planner, 'local_models', return_value=[{'endpoint': ai_planner.ENDPOINTS[0], 'models': ['local']}]), patch.object(ai_planner, 'local_request', return_value={'message': {'content': json.dumps(draft())}}) as request:
            self.assertEqual(ai_planner.local_plan('test', [], 'local', ai_planner.ENDPOINTS[0]), draft())
        body = request.call_args.args[2]
        self.assertFalse(body['stream']); self.assertEqual(body['format'], ai_planner.SCHEMA)
        with self.assertRaises(core.AuditError):
            ai_planner.local_request('https://remote.invalid', '/api/chat')

    def test_http_redirect_refused(self):
        with self.assertRaises(core.AuditError):
            ai_planner.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://remote.invalid')

    def test_codex_opt_in_and_fixed_read_only_arguments(self):
        with self.assertRaises(core.AuditError): ai_planner.codex_plan('test', [])
        def run(argv, **kwargs):
            Path(argv[argv.index('--output-last-message')+1]).write_text(json.dumps(draft()))
            self.assertNotIn('shell', kwargs)
            self.assertEqual(argv[argv.index('--sandbox')+1], 'read-only')
            self.assertIn('--ephemeral', argv); self.assertIn('--ignore-user-config', argv)
            self.assertNotIn('--dangerously-bypass-approvals-and-sandbox', argv)
            return subprocess.CompletedProcess(argv, 0)
        with patch.object(fusion, 'executable', return_value='/fake/codex'), patch.object(programmer, 'reserve') as reserve, patch.object(ai_planner.subprocess, 'run', side_effect=run):
            self.assertEqual(ai_planner.codex_plan('test', [], True), draft())
        reserve.assert_called_once_with('/fake/codex')

    def test_ssh_notification_is_terminal_only(self):
        with patch.dict(os.environ, MSC_NOTIFICATIONS='1', SSH_CONNECTION='test'), patch.object(notifications.subprocess, 'run') as run, contextlib.redirect_stderr(io.StringIO()) as error:
            result = notifications.required('renewal')
        self.assertEqual(result['channel'], 'terminal'); run.assert_not_called()
        self.assertIn('250', error.getvalue())


if __name__ == '__main__':
    unittest.main()
