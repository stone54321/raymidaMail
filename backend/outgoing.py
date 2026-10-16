"""Persist a reply before sending, then atomically expose its accepted Sent copy."""
import base64
import email.policy
from email.message import EmailMessage
from email.utils import formatdate
import hashlib
import json
from pathlib import Path
import time
import uuid
from auth_state import atomic_write, locked, USERNAME


def _mime(payload, send_id, username):
    message = EmailMessage(policy=email.policy.SMTP)
    message['From'] = payload['from']
    message['To'] = ', '.join(payload['to'])
    message['Subject'] = payload['subject']
    message['Date'] = formatdate(localtime=False, usegmt=True)
    for name, value in payload.get('headers', {}).items():
        message[name] = value
    if 'Message-ID' not in message:
        message['Message-ID'] = f'<raymida-sent-{send_id}-{username}@localhost>'
    message.set_content(payload['text'])
    for item in payload.get('attachments', []):
        data = base64.b64decode(item['content'], validate=True)
        message.add_attachment(data, maintype='application', subtype='octet-stream', filename=item['filename'])
    return message.as_bytes()


def _finish(root, state, message_file, send_id):
    sent = root / 'sent'
    sent.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = sent / f'{send_id}.eml'
    if not destination.exists():
        message_file.replace(destination)
        # Commit the directory entry before reporting success.
        import os
        fd = os.open(sent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return state['provider_id']


def send_and_store(mail_dir, username, send_id, payload, submit):
    if not USERNAME.fullmatch(username):
        raise ValueError('Invalid sender')
    send_id = str(uuid.UUID(send_id))
    root = Path(mail_dir) / username
    outgoing = root / '.outgoing'
    outgoing.mkdir(parents=True, exist_ok=True, mode=0o700)
    outgoing.chmod(0o700)
    state_file = outgoing / f'{send_id}.json'
    message_file = outgoing / f'{send_id}.eml'
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
    fingerprint = hashlib.sha256(canonical).hexdigest()
    with locked(outgoing / f'{send_id}.lock'):
        if state_file.exists():
            state = json.loads(state_file.read_text())
            if state['fingerprint'] != fingerprint:
                raise ValueError('Send identifier already used for different contents')
            if state['status'] == 'accepted':
                return _finish(root, state, message_file, send_id)
            if time.time() - state['created'] > 23 * 60 * 60:
                raise ValueError('Old uncertain send: check provider status before sending again')
        else:
            raw = _mime(payload, send_id, username)
            atomic_write(message_file, raw)
            state = {'status': 'pending', 'created': time.time(), 'fingerprint': fingerprint}
            atomic_write(state_file, json.dumps(state).encode())
        provider_id = submit(payload, f'raymida/{username}/{send_id}')
        state.update(status='accepted', provider_id=provider_id)
        atomic_write(state_file, json.dumps(state).encode())
        return _finish(root, state, message_file, send_id)


def recover_accepted(mail_dir, username):
    root = Path(mail_dir) / username
    outgoing = root / '.outgoing'
    if not outgoing.exists():
        return
    for state_file in outgoing.glob('*.json'):
        send_id = state_file.stem
        try:
            uuid.UUID(send_id)
            with locked(outgoing / f'{send_id}.lock'):
                state = json.loads(state_file.read_text())
                if state['status'] == 'accepted':
                    _finish(root, state, outgoing / f'{send_id}.eml', send_id)
        except (OSError, ValueError, KeyError):
            # Keep recovery data; reading Sent must not resubmit to the provider.
            continue
