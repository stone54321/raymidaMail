"""Failure-path tests; all users, mailboxes and provider responses are synthetic."""
import base64
from concurrent.futures import ThreadPoolExecutor
import contextlib
import email
import email.policy
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
import auth_state
import outgoing
import pochta_api
import r2_sync
from test_adversarial_security import _invoke_handler


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / 'users.json'
        self.users = {
            'alice': {'password_hash': 'old-hash', 'api_key': 'old-key', 'extra': 'keep'},
            'bob': {'password_hash': 'bob-hash', 'api_key': 'bob-key'},
        }
        auth_state.atomic_write(self.path, json.dumps(self.users).encode())

    def test_expiry_tampering_and_password_revocation(self):
        token = auth_state.issue_session('alice', self.users['alice'], now=1000)
        self.assertEqual(auth_state.session_user(token, self.users, now=1001), 'alice')
        self.assertIsNone(auth_state.session_user(token, self.users, now=1000 + auth_state.SESSION_TTL))
        self.assertIsNone(auth_state.session_user(token[:-1] + ('0' if token[-1] != '0' else '1'), self.users, now=1001))
        self.assertIsNone(auth_state.session_user('old-key', self.users, now=1001))
        auth_state.set_password(self.path, 'alice', 'new-hash', expected_hash='old-hash')
        updated = json.loads(self.path.read_text())
        self.assertIsNone(auth_state.session_user(token, updated, now=1001))
        self.assertNotEqual(updated['alice']['api_key'], 'old-key')
        self.assertEqual(updated['alice']['extra'], 'keep')
        self.assertEqual(updated['bob'], self.users['bob'])
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_concurrent_updates_preserve_other_accounts_and_fail_stale_password(self):
        with ThreadPoolExecutor(2) as pool:
            list(pool.map(lambda name: auth_state.set_password(self.path, name, name + '-new'), ('alice', 'bob')))
        users = json.loads(self.path.read_text())
        self.assertEqual(users['alice']['password_hash'], 'alice-new')
        self.assertEqual(users['bob']['password_hash'], 'bob-new')
        with self.assertRaises(ValueError):
            auth_state.set_password(self.path, 'alice', 'stale', expected_hash='old-hash')

    def test_password_api_replaces_session_and_rejects_old_cookie_and_bearer(self):
        import bcrypt
        user = auth_state.set_password(self.path, 'alice', bcrypt.hashpw(b'old-password-123', bcrypt.gensalt(rounds=4)).decode())
        old = auth_state.issue_session('alice', user)
        with patch.object(pochta_api, 'USERS_FILE', self.path):
            def request(method, path, token=old, body=None, bearer=False):
                headers = {'Authorization': 'Bearer ' + token} if bearer else {'Cookie': 'auth_key=' + token}
                return _invoke_handler(pochta_api.MailAPIHandler, method, path, headers=headers, body=json.dumps(body).encode() if body is not None else b'')
            self.assertEqual(request('GET', '/api/me')[0], 200)
            self.assertEqual(request('POST', '/api/password', body={'old_password': 'wrong', 'new_password': 'new-password-456'})[0], 400)
            self.assertEqual(request('GET', '/api/me')[0], 200)
            status, headers, _ = request('POST', '/api/password', body={'old_password': 'old-password-123', 'new_password': 'new-password-456'})
            self.assertEqual(status, 200)
            new = headers['set-cookie'].split(';', 1)[0].split('=', 1)[1]
            self.assertEqual(request('GET', '/api/me')[0], 403)
            self.assertEqual(request('GET', '/api/me', user['api_key'], bearer=True)[0], 403)
            self.assertEqual(request('GET', '/api/me', new)[0], 200)
            self.assertEqual(request('GET', '/api/me', user['api_key'])[0], 403)
            status, headers, _ = request('POST', '/api/logout', new, {})
            self.assertEqual(status, 200)
            self.assertIn('Max-Age=0', headers['set-cookie'])


class SentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.send_id = str(uuid.uuid4())
        self.payload = {
            'from': 'Alice <alice@raymida.com>', 'to': ['customer@example.test'],
            'subject': 'Ответ клиенту', 'text': 'Тестовый ответ',
            'headers': {'Message-ID': '<reply@example.test>', 'In-Reply-To': '<original@example.test>'},
            'attachments': [{'filename': 'пример.txt', 'content': base64.b64encode(b'attachment bytes').decode()}],
        }

    def send(self, provider):
        return outgoing.send_and_store(self.root, 'alice', self.send_id, self.payload, provider)

    def test_mime_attachments_and_retry_are_stored_once(self):
        provider = MagicMock(return_value='provider-accepted')
        with ThreadPoolExecutor(4) as pool:
            self.assertEqual(list(pool.map(lambda _: self.send(provider), range(4))), ['provider-accepted'] * 4)
        provider.assert_called_once()
        self.assertEqual(provider.call_args.args[1], 'raymida/alice/' + self.send_id)
        files = list((self.root / 'alice/sent').iterdir())
        self.assertEqual(len(files), 1)
        msg = email.message_from_bytes(files[0].read_bytes(), policy=email.policy.default)
        self.assertEqual(str(msg['Subject']), self.payload['subject'])
        self.assertEqual(msg['In-Reply-To'], '<original@example.test>')
        self.assertEqual(msg.get_body().get_content().strip(), self.payload['text'])
        self.assertEqual(list(msg.iter_attachments())[0].get_payload(decode=True), b'attachment bytes')
        self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)
        with patch.object(pochta_api, 'MAIL_DIR', self.root):
            self.assertEqual(pochta_api.get_emails('alice'), [])
            self.assertEqual(len(pochta_api.get_emails('alice', 'sent')), 1)
            self.assertEqual(len(pochta_api.search_emails('alice', 'customer@example.test', 'sent')), 1)
            self.assertEqual(pochta_api.get_attachment('alice', 'sent/' + files[0].name, 0)[0], b'attachment bytes')
            self.assertIsNone(pochta_api.get_email('bob', 'sent/' + files[0].name))
            self.assertIsNone(pochta_api.get_email('bob', 'sent/../../alice/sent/' + files[0].name))

    def test_provider_failure_is_not_sent_and_retry_uses_same_key(self):
        provider = MagicMock(side_effect=[TimeoutError('lost acknowledgement'), 'provider-accepted'])
        with self.assertRaises(TimeoutError):
            self.send(provider)
        self.assertFalse((self.root / 'alice/sent').exists())
        self.assertEqual(self.send(provider), 'provider-accepted')
        self.assertEqual(provider.call_args_list[0], provider.call_args_list[1])

    def test_accepted_message_recovers_after_local_commit_failure_without_resending(self):
        provider = MagicMock(return_value='accepted')
        with patch.object(outgoing, '_finish', side_effect=OSError('disk temporarily unavailable')):
            with self.assertRaises(OSError):
                self.send(provider)
        outgoing.recover_accepted(self.root, 'alice')
        self.assertEqual(self.send(provider), 'accepted')
        provider.assert_called_once()
        self.assertTrue((self.root / 'alice/sent' / (self.send_id + '.eml')).is_file())

    def test_changed_payload_and_old_uncertain_retries_are_blocked(self):
        provider = MagicMock(side_effect=TimeoutError())
        with self.assertRaises(TimeoutError):
            self.send(provider)
        self.payload['text'] = 'changed'
        with self.assertRaisesRegex(ValueError, 'different contents'):
            self.send(provider)
        self.payload['text'] = 'Тестовый ответ'
        state_file = self.root / 'alice/.outgoing' / (self.send_id + '.json')
        state = json.loads(state_file.read_text())
        state['created'] = time.time() - 24 * 60 * 60
        state_file.write_text(json.dumps(state))
        with self.assertRaisesRegex(ValueError, 'uncertain'):
            self.send(provider)
        self.assertEqual(provider.call_count, 1)

    def test_api_uses_reply_to_and_provider_idempotency(self):
        (self.root / 'alice/new').mkdir(parents=True)
        (self.root / 'alice/cur').mkdir()
        (self.root / 'alice/new/test.eml').write_bytes(b'From: Site <site@raymida.com>\r\nReply-To: customer@example.test\r\nTo: alice@raymida.com\r\nMessage-ID: <original@example.test>\r\n\r\nForm contents')
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.return_value = b'{"id":"accepted"}'
        with patch.object(pochta_api, 'MAIL_DIR', self.root), patch.object(pochta_api, 'RESEND_KEY', 'test-only'), patch.object(pochta_api.urllib.request, 'urlopen', return_value=response) as provider, patch.object(pochta_api, 'load_users', return_value={'alice': {'api_key': 'test-key'}}):
            for _ in range(2):
                status, _, body = _invoke_handler(pochta_api.MailAPIHandler, 'POST', '/api/send', headers={'Authorization': 'Bearer test-key', 'X-Raymida-Send-ID': self.send_id}, body=json.dumps({'id':'new/test.eml', 'subject':'Re: test', 'text':'reply'}).encode())
                self.assertEqual(status, 200, body)
            provider.assert_called_once()
            request = provider.call_args.args[0]
            self.assertEqual(json.loads(request.data)['to'], ['customer@example.test'])
            self.assertEqual(request.get_header('Idempotency-key'), 'raymida/alice/' + self.send_id)


class R2RoutingTests(unittest.TestCase):
    raw = b'From: other@example.test\r\nTo: unrelated@example.test\r\n\r\nBCC message'

    def test_envelope_recipient_overrides_header_and_display_name(self):
        self.assertEqual(r2_sync.queued_mailbox({'Metadata': {'originalTo':'Ray <r.a.y+tag@raymida.com>'}}, self.raw), 'ray')
        self.assertEqual(r2_sync.queued_mailbox({'Metadata': {'originalto':'unreala@raymida.com'}}, b'\r\n'), 'unreala')
        self.assertEqual(r2_sync.queued_mailbox({}, b'To: Tony <tony@raymida.com>\r\n\r\n'), 'tony')

    def test_ambiguous_or_invalid_objects_are_never_guessed(self):
        for metadata, raw in (({}, self.raw), ({'originalto':''}, self.raw), ({}, b'To: ray@raymida.com, tony@raymida.com\r\n\r\n')):
            with self.assertRaises(ValueError):
                r2_sync.queued_mailbox({'Metadata': metadata}, raw)

    def test_one_bad_object_does_not_block_others_and_delete_follows_durable_save(self):
        s3 = MagicMock()
        s3.get_paginator.return_value.paginate.return_value = [{'Contents':[{'Key':'pending/bad.eml'},{'Key':'pending/good.eml'}]}]
        s3.get_object.side_effect = [{'Metadata':{}, 'Body':io.BytesIO(self.raw)}, {'Metadata':{'originalto':'ray@raymida.com'}, 'Body':io.BytesIO(self.raw)}]
        events = []
        s3.delete_object.side_effect = lambda **kw: events.append(('delete', kw['Key']))
        with patch.multiple(r2_sync, R2_ACCOUNT_ID='test', R2_ACCESS_KEY='test', R2_SECRET_KEY='test'), patch.object(r2_sync.boto3, 'client', return_value=s3), patch.object(r2_sync, 'save_to_maildir', side_effect=lambda *args: events.append(('save', args[0]))), contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(r2_sync.sync_from_r2())
        self.assertEqual(events, [('save','ray'), ('delete','pending/good.eml')])

    def test_failed_local_save_keeps_r2_object(self):
        s3 = MagicMock()
        s3.get_paginator.return_value.paginate.return_value = [{'Contents':[{'Key':'pending/good.eml'}]}]
        s3.get_object.return_value = {'Metadata':{'originalto':'ray@raymida.com'}, 'Body':io.BytesIO(self.raw)}
        with patch.multiple(r2_sync, R2_ACCOUNT_ID='test', R2_ACCESS_KEY='test', R2_SECRET_KEY='test'), patch.object(r2_sync.boto3, 'client', return_value=s3), patch.object(r2_sync, 'save_to_maildir', side_effect=OSError('disk full')), contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(r2_sync.sync_from_r2())
        s3.delete_object.assert_not_called()


if __name__ == '__main__':
    unittest.main()
