import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { test } from 'node:test';
import assert from 'node:assert/strict';

function script(name) {
    return readFileSync(new URL(`../src/ZeroFactor/Slices/${name}.cshtml`, import.meta.url), 'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
}

test('session iframe detects login, logout and account changes without polling the server', async () => {
    let listener;
    const requests = [];
    const replies = [];
    const document = { cookie: '' };
    runInNewContext(script('SessionStatus'), {
        document, URL,
        location: { origin: 'https://auth.test', pathname: '/prefix/realms/test/protocol/openid-connect/login-status-iframe.html' },
        window: { addEventListener: (_, callback) => { listener = callback; } },
        fetch: async url => { requests.push(url); return { ok: true }; },
    });
    const send = (data, origin = 'https://app.test') => listener({ data, origin, source: { postMessage: (...args) => replies.push(args) } });
    await send('web ');
    assert.deepEqual(replies.pop(), ['unchanged', 'https://app.test']);
    document.cookie = 'unrelated=1; ZF_SESSION_STATUS=first';
    await send('web ');
    assert.equal(replies.pop()[0], 'changed');
    await send('web first');
    assert.equal(replies.pop()[0], 'unchanged');
    document.cookie = 'ZF_SESSION_STATUS=second';
    await send('web first');
    assert.equal(replies.pop()[0], 'changed');
    document.cookie = '';
    await send('web second');
    assert.equal(replies.pop()[0], 'changed');
    await send('other ');
    assert.equal(replies.pop()[0], 'error');
    await send('web ', 'https://evil.test');
    assert.deepEqual(replies.pop(), ['error', 'https://evil.test']);
    await send({ client: 'web' });
    await send('malformed');
    assert.equal(replies.length, 0);
    assert.equal(requests.length, 1);
    assert.equal(requests[0].pathname, '/prefix/realms/test/protocol/openid-connect/login-status-iframe.html/init');
    assert.equal(requests[0].searchParams.get('client_id'), 'web');
    assert.equal(requests[0].searchParams.get('origin'), 'https://app.test');
});

for (const failure of ['denied', 'network']) {
    test(`session iframe reports ${failure} validation as error`, async () => {
        let listener;
        let reply;
        let requests = 0;
        runInNewContext(script('SessionStatus'), {
            document: { cookie: 'ZF_SESSION_STATUS=session' }, URL,
            location: { origin: 'https://auth.test', pathname: '/iframe' },
            window: { addEventListener: (_, callback) => { listener = callback; } },
            fetch: async () => { requests++; if (failure === 'network') throw Error('offline'); return { ok: false }; },
        });
        const event = { data: 'web session', origin: 'https://app.test', source: { postMessage: value => { reply = value; } } };
        await listener(event);
        assert.equal(reply, 'error');
        await listener(event);
        assert.equal(requests, 1);
    });
}

test('cookie probe sets a short-lived cookie then navigates to step 2', async () => {
    for (const protocol of ['http:', 'https:']) {
        const location = { protocol };
        const document = { cookie: '' };
        await runInNewContext(script('CookieProbe'), { location, document });
        assert.equal(location.href, 'step2.html');
        assert.match(document.cookie, /ZF_COOKIE_PROBE=1; Max-Age=60/);
        assert.equal(document.cookie.includes('SameSite=None; Secure'), protocol === 'https:');
    }
});

test('cookie probe signals unsupported when storage access is denied', async () => {
    let reply;
    await runInNewContext(script('CookieProbe'), {
        document: { hasStorageAccess: async () => false, requestStorageAccess: async () => { throw Error('denied'); } },
        parent: { postMessage: value => { reply = value; } },
    });
    assert.equal(reply, 'unsupported');
});

test('cookie probe result reports actual cookie access and cleans up', () => {
    for (const cookie of ['', 'ZF_COOKIE_PROBE=1', 'other=1; ZF_COOKIE_PROBE=1']) {
        const document = { cookie };
        let reply;
        runInNewContext(script('CookieProbeResult'), {
            document, location: { protocol: 'https:' }, parent: { postMessage: value => { reply = value; } },
        });
        assert.equal(reply, cookie ? 'supported' : 'unsupported');
        assert.match(document.cookie, /ZF_COOKIE_PROBE=; Max-Age=0/);
    }
});
