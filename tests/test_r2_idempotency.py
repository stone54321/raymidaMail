"""R2 replay and crash tests: temporary mailboxes, fake objects, no credentials."""
from concurrent.futures import ThreadPoolExecutor
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

BACKEND = Path(__file__).resolve().parents[1] / 'backend'
sys.path.insert(0, str(BACKEND))
import maildir_delivery
import priyomnik
import r2_sync


class SimulatedCrash(BaseException):
    pass


class R2IdempotencyTests(unittest.TestCase):
    raw = b'From: sender@example.test\r\nTo: hidden@example.test\r\nSubject: BCC\r\n\r\nMessage'
    key = 'pending/1730000000000-queue-uuid.eml'

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'mail'
        self.addCleanup(patch.stopall)
        patch.multiple(r2_sync, LOCAL_MAIL_DIR=self.root, MAIL_DOMAIN='raymida.com',
                       R2_ACCOUNT_ID='test-account', R2_ACCESS_KEY='test-key',
                       R2_SECRET_KEY='test-secret', R2_BUCKET_NAME='test-bucket').start()
        self.object_id = r2_sync.object_identity(self.key)
        self.receipt = self.root / '.r2-receipts' / (self.object_id + '.json')
        self.filename = f'r2-{self.object_id}.raymida'
        self.s3 = MagicMock()
        self.s3.get_paginator.return_value.paginate.return_value = [{'Contents': [{'Key': self.key}]}]
        self.s3.get_object.side_effect = lambda **kwargs: {
            'Metadata': {'originalTo': 'Ray <r.a.y+tag@raymida.com>'},
            'Body': io.BytesIO(self.raw),
        }
        patch.object(r2_sync.boto3, 'client', return_value=self.s3).start()

    def sync(self):
        with contextlib.redirect_stdout(io.StringIO()):
            return r2_sync.sync_from_r2()

    def messages(self):
        return sorted(path for folder in ('new', 'cur') for path in (self.root / 'ray' / folder).glob('*'))

    def deliver(self):
        return r2_sync.save_to_maildir('ray', self.raw, self.object_id)

    def subprocess(self, code):
        # Deliberately do not inherit provider credentials or production paths.
        environment = {'PATH': os.defpath, 'PYTHONPATH': str(BACKEND),
                       'MAIL_DIR': str(self.root), 'MAIL_DOMAIN': 'raymida.com',
                       'R2_ACCOUNT_ID': 'test-account', 'R2_ACCESS_KEY': 'test-key',
                       'R2_SECRET_KEY': 'test-secret', 'R2_BUCKET_NAME': 'test-bucket',
                       'AWS_EC2_METADATA_DISABLED': 'true'}
        return subprocess.Popen([sys.executable, '-c', code], env=environment,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_success_is_durable_before_delete_and_preserves_bcc(self):
        def delete(**kwargs):
            self.assertEqual(kwargs, {'Bucket': 'test-bucket', 'Key': self.key})
            self.assertEqual(json.loads(self.receipt.read_text())['status'], 'committed')
            self.assertEqual(self.messages()[0].read_bytes(), self.raw)
        self.s3.delete_object.side_effect = delete
        self.assertTrue(self.sync())
        self.assertEqual(len(self.messages()), 1)
        self.assertEqual(self.messages()[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list((self.root / 'ray/tmp').iterdir()), [])
        self.s3.delete_object.assert_called_once()

    def test_crash_before_delete_then_replay(self):
        self.s3.delete_object.side_effect = SimulatedCrash()
        with self.assertRaises(SimulatedCrash):
            self.sync()
        original = self.messages()[0]
        inode = original.stat().st_ino
        self.s3.delete_object.side_effect = None
        for _ in range(4):
            self.assertTrue(self.sync())
        self.assertEqual(self.messages(), [original])
        self.assertEqual(original.stat().st_ino, inode)

    def test_delete_failure_retries_without_delivering_again(self):
        self.s3.delete_object.side_effect = OSError('R2 unavailable')
        self.assertFalse(self.sync())
        self.s3.delete_object.side_effect = None
        self.assertTrue(self.sync())
        self.assertEqual(len(self.messages()), 1)

    def test_crash_after_publish_before_receipt_recovers_in_new(self):
        original = maildir_delivery._publish
        def crash(*args):
            original(*args)
            raise SimulatedCrash()
        with patch.object(maildir_delivery, '_publish', side_effect=crash):
            with self.assertRaises(SimulatedCrash):
                self.sync()
        self.s3.delete_object.assert_not_called()
        self.assertEqual(json.loads(self.receipt.read_text())['status'], 'publishing')
        self.assertTrue(self.sync())
        self.assertEqual(len(self.messages()), 1)

    def test_crash_after_publish_then_move_to_cur_with_flags(self):
        original = maildir_delivery._publish
        def crash(*args):
            original(*args)
            raise SimulatedCrash()
        with patch.object(maildir_delivery, '_publish', side_effect=crash):
            with self.assertRaises(SimulatedCrash):
                self.deliver()
        existing = self.messages()[0]
        destination = self.root / 'ray/cur' / (self.filename + ':2,S')
        existing.rename(destination)
        self.assertTrue(self.sync())
        self.assertEqual(self.messages(), [destination])

    def test_receipt_survives_user_deletion(self):
        self.deliver().unlink()
        self.assertTrue(self.sync())
        self.assertEqual(self.messages(), [])

    def test_uncertain_publication_missing_message_fails_closed(self):
        with patch.object(maildir_delivery, '_publish', side_effect=SimulatedCrash()):
            with self.assertRaises(SimulatedCrash):
                self.deliver()
        self.assertFalse(self.sync())
        self.assertEqual(self.messages(), [])
        self.s3.delete_object.assert_not_called()

    def test_interrupted_partial_staging_is_rewritten_before_publication(self):
        original = maildir_delivery._stage
        def interrupted(mailbox_dir, filename, raw_data):
            (mailbox_dir / 'tmp' / filename).write_bytes(b'partial')
            raise SimulatedCrash()
        with patch.object(maildir_delivery, '_stage', side_effect=interrupted):
            with self.assertRaises(SimulatedCrash):
                self.deliver()
        self.assertEqual(json.loads(self.receipt.read_text())['status'], 'writing')
        self.assertTrue(self.sync())
        self.assertEqual(self.messages()[0].read_bytes(), self.raw)
        self.assertEqual(list((self.root / 'ray/tmp').iterdir()), [])
        self.assertIs(maildir_delivery._stage, original)

    def test_corrupt_receipt_with_verified_message_is_repaired(self):
        self.deliver()
        self.receipt.write_bytes(b'{broken')
        self.assertTrue(self.sync())
        self.assertEqual(json.loads(self.receipt.read_text())['status'], 'committed')
        self.assertEqual(len(self.messages()), 1)

    def test_incomplete_receipt_with_verified_message_is_repaired(self):
        self.deliver()
        self.receipt.write_text(json.dumps({'fingerprint': hashlib.sha256(self.raw).hexdigest()}))
        self.assertTrue(self.sync())
        self.assertEqual(len(self.messages()), 1)

    def test_missing_receipt_with_verified_message_is_repaired(self):
        original = self.deliver()
        self.receipt.unlink()
        self.assertTrue(self.sync())
        self.assertEqual(self.messages(), [original])

    def test_reader_move_during_verification_does_not_create_a_copy(self):
        original = self.deliver()
        state = json.loads(self.receipt.read_text())
        state['status'] = 'publishing'
        self.receipt.write_text(json.dumps(state))
        verify = maildir_delivery._verify_file
        destination = self.root / 'ray/cur' / self.filename
        def moving_reader(path, fingerprint):
            if path == original:
                path.rename(destination)
            return verify(path, fingerprint)
        with patch.object(maildir_delivery, '_verify_file', side_effect=moving_reader):
            self.assertTrue(self.sync())
        self.assertEqual(self.messages(), [destination])

    def test_failed_commit_receipt_is_recovered_without_another_publication(self):
        write = maildir_delivery._write_receipt
        def fail_commit(path, state):
            if state['status'] == 'committed':
                raise OSError('receipt write interrupted')
            write(path, state)
        with patch.object(maildir_delivery, '_write_receipt', side_effect=fail_commit):
            self.assertFalse(self.sync())
        self.s3.delete_object.assert_not_called()
        original = self.messages()[0]
        self.assertTrue(self.sync())
        self.assertEqual(self.messages(), [original])

    def test_failed_commit_directory_fsync_is_not_acknowledged(self):
        flush = maildir_delivery._fsync_directory
        def fail_commit(path):
            if path == self.receipt.parent and self.receipt.exists():
                if json.loads(self.receipt.read_text())['status'] == 'committed':
                    raise OSError('receipt directory fsync failed')
            flush(path)
        with patch.object(maildir_delivery, '_fsync_directory', side_effect=fail_commit):
            self.assertFalse(self.sync())
        self.s3.delete_object.assert_not_called()
        self.assertTrue(self.sync())
        self.assertEqual(len(self.messages()), 1)

    def test_corrupt_or_incomplete_receipt_without_message_is_retained(self):
        self.receipt.parent.mkdir(parents=True)
        for contents in ('{broken', 'null', '[]', '{}', '{"status":"committed"}'):
            with self.subTest(contents=contents):
                self.receipt.write_text(contents)
                self.assertFalse(self.sync())
                self.assertEqual(self.messages(), [])
                self.s3.delete_object.assert_not_called()

    def test_uncommitted_receipt_temp_file_is_not_trusted(self):
        self.receipt.parent.mkdir(parents=True)
        self.receipt.with_suffix('.json.tmp').write_bytes(b'{partial')
        self.assertTrue(self.sync())
        self.assertEqual(len(self.messages()), 1)

    def test_corrupt_published_message_is_not_acknowledged(self):
        original = maildir_delivery._publish
        def crash(*args):
            original(*args)
            raise SimulatedCrash()
        with patch.object(maildir_delivery, '_publish', side_effect=crash):
            with self.assertRaises(SimulatedCrash):
                self.deliver()
        self.messages()[0].write_bytes(b'corrupt')
        self.assertFalse(self.sync())
        self.s3.delete_object.assert_not_called()
        self.assertEqual(len(self.messages()), 1)

    def test_concurrent_threads_deliver_one_message(self):
        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(lambda _: self.deliver(), range(24)))
        self.assertEqual(len(self.messages()), 1)
        self.assertEqual(json.loads(self.receipt.read_text())['status'], 'committed')

    def test_concurrent_processes_deliver_one_message(self):
        code = f'import r2_sync; r2_sync.save_to_maildir("ray", {self.raw!r}, {self.object_id!r})'
        processes = [self.subprocess(code) for _ in range(4)]
        for process in processes:
            output, error = process.communicate(timeout=30)
            self.assertEqual(process.returncode, 0, (output, error))
        self.assertEqual(len(self.messages()), 1)

    def test_hard_process_exit_after_publish_then_fresh_sync(self):
        code = f'''
import os
import maildir_delivery
import r2_sync
publish = maildir_delivery._publish
def crash(*args):
    publish(*args)
    os._exit(71)
maildir_delivery._publish = crash
r2_sync.save_to_maildir('ray', {self.raw!r}, {self.object_id!r})
'''
        process = self.subprocess(code)
        output, error = process.communicate(timeout=30)
        self.assertEqual(process.returncode, 71, (output, error))
        self.assertTrue(self.sync())
        # Retry again in another interpreter, with a newly mocked S3 client.
        process = self.subprocess(f'''
import io
from unittest.mock import MagicMock, patch
import r2_sync
s3 = MagicMock()
s3.get_paginator.return_value.paginate.return_value = [{{'Contents':[{{'Key':{self.key!r}}}]}}]
s3.get_object.return_value = {{'Metadata':{{'originalto':'ray@raymida.com'}}, 'Body':io.BytesIO({self.raw!r})}}
with patch.object(r2_sync.boto3, 'client', return_value=s3):
    assert r2_sync.sync_from_r2()
    s3.delete_object.assert_called_once()
''')
        output, error = process.communicate(timeout=30)
        self.assertEqual(process.returncode, 0, (output, error))
        self.assertEqual(len(self.messages()), 1)

    def test_same_bytes_different_objects_remain_distinct(self):
        self.deliver()
        r2_sync.save_to_maildir('ray', self.raw, r2_sync.object_identity('pending/another.eml'))
        self.assertEqual(len(self.messages()), 2)

    def test_identity_is_namespaced_and_independent_of_content(self):
        with patch.object(r2_sync, 'R2_BUCKET_NAME', 'other-bucket'):
            self.assertNotEqual(r2_sync.object_identity(self.key), self.object_id)
        with patch.object(r2_sync, 'R2_ACCOUNT_ID', 'other-account'):
            self.assertNotEqual(r2_sync.object_identity(self.key), self.object_id)

    def test_changed_bytes_or_recipient_for_same_object_are_rejected(self):
        self.deliver()
        with self.assertRaises(ValueError):
            r2_sync.save_to_maildir('ray', self.raw + b'changed', self.object_id)
        with self.assertRaises(ValueError):
            r2_sync.save_to_maildir('tony', self.raw, self.object_id)
        self.assertEqual(len(self.messages()), 1)
        self.assertEqual(list((self.root / 'tony/new').iterdir()), [])

    def test_invalid_routing_does_not_block_next_object(self):
        bad = [{}, {'originalto': ''}, {'originalto': 'ray@raymida.com, tony@raymida.com'},
               {'originalto': 'someone@else.test'}, {'originalto': None},
               {'originalto': 'ray@raymida.com\r\nTo: tony@raymida.com'},
               {'originalTo': 'ray@raymida.com', 'originalto': 'tony@raymida.com'}]
        keys = [f'pending/bad-{index}.eml' for index in range(len(bad))] + [self.key]
        self.s3.get_paginator.return_value.paginate.return_value = [{'Contents': [{'Key': key} for key in keys]}]
        self.s3.get_object.side_effect = [
            {'Metadata': metadata, 'Body': io.BytesIO(self.raw)} for metadata in bad
        ] + [{'Metadata': {'originalto': 'ray@raymida.com'}, 'Body': io.BytesIO(self.raw)}]
        self.assertFalse(self.sync())
        self.assertEqual(len(self.messages()), 1)
        self.s3.delete_object.assert_called_once_with(Bucket='test-bucket', Key=self.key)

    def test_ambiguous_legacy_to_is_retained(self):
        self.s3.get_object.side_effect = lambda **kwargs: {
            'Body': io.BytesIO(b'To: ray@raymida.com, tony@raymida.com\r\n\r\nBody')}
        self.assertFalse(self.sync())
        self.s3.delete_object.assert_not_called()

    def test_local_write_or_fsync_failure_prevents_r2_delete(self):
        for operation in ('_stage', '_flush_maildir', '_write_receipt'):
            with self.subTest(operation=operation), patch.object(maildir_delivery, operation, side_effect=OSError('disk unavailable')):
                self.assertFalse(self.sync())
                self.s3.delete_object.assert_not_called()

    def test_failure_at_each_fsync_boundary_never_acknowledges_or_duplicates(self):
        fsync = os.fsync
        with patch.object(os, 'fsync', wraps=fsync) as calls:
            self.assertTrue(self.sync())
        boundary_count = calls.call_count
        for boundary in range(1, boundary_count + 1):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory:
                self.root = Path(directory) / 'mail'
                self.receipt = self.root / '.r2-receipts' / (self.object_id + '.json')
                count = 0
                def interrupted(descriptor):
                    nonlocal count
                    count += 1
                    if count == boundary:
                        raise OSError('injected fsync failure')
                    fsync(descriptor)
                self.s3.delete_object.reset_mock()
                with patch.object(r2_sync, 'LOCAL_MAIL_DIR', self.root):
                    with patch.object(os, 'fsync', side_effect=interrupted):
                        self.assertFalse(self.sync())
                    self.s3.delete_object.assert_not_called()
                    completed = self.sync()
                self.assertLessEqual(len(self.messages()), 1)
                if completed:
                    self.assertEqual(len(self.messages()), 1)
                    self.assertEqual(json.loads(self.receipt.read_text())['status'], 'committed')
                else:
                    self.assertEqual(json.loads(self.receipt.read_text())['status'], 'publishing')
                    self.s3.delete_object.assert_not_called()

    def test_form_direct_delivery_and_multiple_r2_objects_share_one_message(self):
        request_id = 'ba6143cc-e85f-4f28-aaf0-e17fb8a028c3'
        raw = (f'X-Raymida-Source: website\r\nX-Raymida-Request-ID: {request_id}\r\n'
               f'Message-ID: <raymida-form-{request_id}-ray@raymida.com>\r\n'
               'To: ray@raymida.com\r\n\r\nForm').encode()
        with patch.object(priyomnik, 'MAIL_DIR', self.root), patch.object(priyomnik, 'MAIL_DOMAIN', 'raymida.com'):
            path = priyomnik.save_to_maildir('ray@raymida.com', raw)
            for key in (self.key, 'pending/second-form.eml'):
                r2_sync.save_to_maildir('ray', raw, r2_sync.object_identity(key))
            self.assertEqual(self.messages(), [path])
            path.unlink()
            priyomnik.save_to_maildir('ray@raymida.com', raw)
            r2_sync.save_to_maildir('ray', raw, r2_sync.object_identity('pending/third-form.eml'))
            self.assertEqual(self.messages(), [])

    def test_legacy_form_receipt_is_preserved(self):
        request_id = 'ba6143cc-e85f-4f28-aaf0-e17fb8a028c3'
        raw = (f'X-Raymida-Source: website\r\nX-Raymida-Request-ID: {request_id}\r\n'
               f'Message-ID: <raymida-form-{request_id}-ray@raymida.com>\r\n\r\nForm').encode()
        receipt = self.root / '.form-receipts/ray' / (request_id + '.json')
        receipt.parent.mkdir(parents=True)
        receipt.write_text(json.dumps({'fingerprint': hashlib.sha256(raw).hexdigest()}))
        r2_sync.save_to_maildir('ray', raw, self.object_id)
        self.assertEqual(self.messages(), [])
        self.assertEqual(json.loads(receipt.read_text())['status'], 'committed')


if __name__ == '__main__':
    unittest.main()
