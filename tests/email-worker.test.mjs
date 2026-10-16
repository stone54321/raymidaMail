import {test, mock} from 'node:test';
import assert from 'node:assert/strict';
import worker from '../cloudflare/email-worker.mjs';

const raw = 'From: sender@example.test\r\nTo: undisclosed@example.test\r\n\r\nExample';
function message() {
  return {raw: new Response(raw).body, to:'ray@raymida.com', from:'sender@example.test', setReject:mock.fn()};
}
const base = {PRIYOMNIK:'https://receiver.example.test/inbound', KEY:'test-only'};

test('online receiver accepts the full MIME and envelope address', async () => {
  const fetch = mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(options.headers['X-Original-To'], 'ray@raymida.com');
    assert.equal(new TextDecoder().decode(options.body), raw);
    assert.equal(options.signal.aborted, false);
    return new Response('ok');
  });
  try {
    const mail = message();
    const put = mock.fn();
    await worker.email(mail, {...base, MAIL_QUEUE:{put}}, {});
    assert.equal(put.mock.callCount(), 0);
    assert.equal(mail.setReject.mock.callCount(), 0);
  } finally {fetch.mock.restore();}
});

for (const failure of ['timeout', 'bad-status']) {
  test(`receiver ${failure} falls back to awaited R2 write with original recipient`, async () => {
    const fetch = mock.method(globalThis, 'fetch', async () => {
      if (failure === 'timeout') throw new DOMException('Timed out','TimeoutError');
      return new Response('failed', {status:503});
    });
    try {
      let stored = false;
      const put = mock.fn(async (key, bytes, options) => {
        await Promise.resolve();
        assert.match(key, /^pending\/.*\.eml$/);
        assert.equal(new TextDecoder().decode(bytes), raw);
        assert.equal(options.customMetadata.originalTo, 'ray@raymida.com');
        stored = true;
      });
      const mail = message();
      await worker.email(mail, {...base, MAIL_QUEUE:{put}}, {});
      assert.equal(stored, true);
      assert.equal(mail.setReject.mock.callCount(), 0);
    } finally {fetch.mock.restore();}
  });
}

for (const queue of [undefined, {put:async () => {throw new Error('R2 down');}}]) {
  test(`total delivery failure rejects the SMTP message (${queue ? 'R2 failure' : 'missing R2'})`, async () => {
    const fetch = mock.method(globalThis, 'fetch', async () => {throw new Error('offline');});
    try {
      const mail = message();
      await worker.email(mail, {...base, MAIL_QUEUE:queue}, {});
      assert.equal(mail.setReject.mock.callCount(), 1);
      assert.match(mail.setReject.mock.calls[0].arguments[0], /could not store/);
    } finally {fetch.mock.restore();}
  });
}
