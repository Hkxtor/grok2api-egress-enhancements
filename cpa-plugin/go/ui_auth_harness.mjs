/* ui_auth_harness.mjs — ui_auth.js 的 Node 行为测试（由 ui_auth_test.go 调用）
 *
 * 只验证真实行为：密钥解析（官方存储格式 / 旧版格式 / 误读拒绝）、
 * 失败分类、轮询策略。不使用 DOM，不需要额外依赖。
 * 输出：每行 "ok - <name>"，失败时 "not ok - <name>: <detail>" 并以非 0 退出。
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const source = fs.readFileSync(path.join(here, 'ui_auth.js'), 'utf8');
// eslint-disable-next-line no-new-func
new Function(source)();
const A = globalThis.EgressUIAuth;

let failed = 0;
function check(name, condition, detail) {
  if (condition) {
    console.log('ok - ' + name);
    return;
  }
  failed += 1;
  console.log('not ok - ' + name + ': ' + (detail === undefined ? 'assertion failed' : detail));
}
function equal(name, actual, expected) {
  check(name, actual === expected, 'got ' + JSON.stringify(actual) + ', want ' + JSON.stringify(expected));
}

if (!A) {
  console.log('not ok - module export: globalThis.EgressUIAuth missing');
  process.exit(1);
}

const HOST = '127.0.0.1:8317';
const UA = 'Mozilla/5.0 (Macintosh) harness';

function obfuscate(value, host = HOST, ua = UA) {
  const seed = new TextEncoder().encode(A.obfuscationSeed(host, ua));
  const bytes = new TextEncoder().encode(value);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] ^= seed[i % seed.length];
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return A.ENC_PREFIX + btoa(binary);
}
function storage(map) {
  return {
    getItem(key) {
      return Object.prototype.hasOwnProperty.call(map, key) ? map[key] : null;
    }
  };
}
function authStorePayload(key) {
  return JSON.stringify({
    state: { apiBase: 'http://' + HOST, managementKey: key, rememberPassword: true },
    version: 0
  });
}

// --- 密钥解析：官方 cli-proxy-auth -----------------------------------------
equal(
  'official store (obfuscated) resolves key',
  A.resolveManagementKey(storage({ 'cli-proxy-auth': obfuscate(authStorePayload('mgmt-key-official')) }), HOST, UA),
  'mgmt-key-official'
);
equal(
  'official store (plaintext json) resolves key',
  A.resolveManagementKey(storage({ 'cli-proxy-auth': authStorePayload('mgmt-key-plain') }), HOST, UA),
  'mgmt-key-plain'
);
equal(
  'official store with double-encoded payload resolves key',
  A.resolveManagementKey(
    storage({ 'cli-proxy-auth': obfuscate(JSON.stringify(authStorePayload('mgmt-key-double'))) }),
    HOST,
    UA
  ),
  'mgmt-key-double'
);
equal(
  'official store with triple-encoded payload resolves key',
  A.resolveManagementKey(
    storage({
      'cli-proxy-auth': obfuscate(
        JSON.stringify(JSON.stringify(JSON.stringify({ state: { managementKey: 'mgmt-key-triple' } })))
      )
    }),
    HOST,
    UA
  ),
  'mgmt-key-triple'
);

// --- 密钥解析：旧版/错误来源 ------------------------------------------------
equal(
  'legacy plaintext managementKey resolves key',
  A.resolveManagementKey(storage({ managementKey: 'legacy-plain-key' }), HOST, UA),
  'legacy-plain-key'
);
equal(
  'legacy obfuscated managementKey resolves key',
  A.resolveManagementKey(storage({ managementKey: obfuscate('legacy-enc-key') }), HOST, UA),
  'legacy-enc-key'
);
equal(
  'stale authToken is ignored (panel never writes it)',
  A.resolveManagementKey(
    storage({
      'cli-proxy-auth': obfuscate(authStorePayload('mgmt-key-official')),
      authToken: 'some-other-token'
    }),
    HOST,
    UA
  ),
  'mgmt-key-official'
);
equal(
  'authToken alone never becomes a key',
  A.resolveManagementKey(storage({ authToken: 'some-other-token' }), HOST, UA),
  ''
);
equal('empty storage resolves to empty key', A.resolveManagementKey(storage({}), HOST, UA), '');

// --- 密钥解析：误读必须拒绝，绝不把垃圾当密钥发出去 -------------------------
equal(
  'undecodable ciphertext is rejected',
  A.resolveManagementKey(storage({ 'cli-proxy-auth': A.ENC_PREFIX + '###not-base64###' }), HOST, UA),
  ''
);
equal(
  'legacy slot holding a store object resolves the embedded key',
  A.resolveManagementKey(storage({ managementKey: authStorePayload('mgmt-key-in-blob') }), HOST, UA),
  'mgmt-key-in-blob'
);
equal(
  'legacy slot holding a key-less json blob is rejected',
  A.resolveManagementKey(storage({ managementKey: JSON.stringify({ state: { apiBase: 'http://x' }, version: 0 }) }), HOST, UA),
  ''
);
// 官方条目能读懂但里面没有密钥（未勾「记住密码」）时，它就是权威：
// 不回退到陈年旧值，以免拿过期密钥去烧失败次数。
equal(
  'key-less official store suppresses the legacy fallback',
  A.resolveManagementKey(
    storage({
      'cli-proxy-auth': obfuscate(JSON.stringify({ state: { apiBase: 'http://x', rememberPassword: false }, version: 0 })),
      managementKey: 'stale-legacy-key'
    }),
    HOST,
    UA
  ),
  ''
);
equal(
  'unreadable official store still allows the legacy fallback',
  A.resolveManagementKey(
    storage({ 'cli-proxy-auth': A.ENC_PREFIX + '###broken###', managementKey: 'legacy-migrated-key' }),
    HOST,
    UA
  ),
  'legacy-migrated-key'
);
equal(
  'store without managementKey is rejected',
  A.resolveManagementKey(storage({ 'cli-proxy-auth': obfuscate(JSON.stringify({ state: { apiBase: 'http://x' }, version: 0 })) }), HOST, UA),
  ''
);
equal('multiline value is rejected', A.looksLikeManagementKey('line1\nline2'), false);
equal('oversized value is rejected', A.looksLikeManagementKey('k'.repeat(A.MAX_KEY_LENGTH + 1)), false);
equal('quoted json string is rejected', A.looksLikeManagementKey('"mgmt-key"'), false);
equal('normal key is accepted', A.looksLikeManagementKey('  mgmt-key  '), true);

// --- 失败分类：只有真鉴权失败才算鉴权失败 ----------------------------------
const invalidKey = A.classifyFailure(401, JSON.stringify({ error: 'invalid management key' }));
check('401 invalid management key classified', invalidKey.kind === 'invalid_key' && invalidKey.auth === true, JSON.stringify(invalidKey));
const missingKey = A.classifyFailure(401, JSON.stringify({ error: 'missing management key' }));
check('401 missing management key classified', missingKey.kind === 'invalid_key' && missingKey.auth === true, JSON.stringify(missingKey));
const banned = A.classifyFailure(403, JSON.stringify({ error: 'IP banned due to too many failed attempts. Try again in 14m49s' }));
check('403 ban classified with countdown', banned.kind === 'banned' && banned.auth === true, JSON.stringify(banned));
equal('ban countdown parsed', banned.retrySeconds, 14 * 60 + 49);
const pluginForbidden = A.classifyFailure(403, JSON.stringify({ error: { code: 'forbidden', message: 'forbidden' } }));
check('plugin business 403 is not an auth failure', pluginForbidden.kind === 'business' && pluginForbidden.auth === false, JSON.stringify(pluginForbidden));
const server = A.classifyFailure(500, 'boom');
check('500 classified as server', server.kind === 'server' && server.auth === false, JSON.stringify(server));
const network = A.classifyFailure(0, '');
check('transport failure classified as network', network.kind === 'network' && network.auth === false, JSON.stringify(network));
check(
  'banned message survives plain-text body',
  A.classifyFailure(403, 'IP banned due to too many failed attempts. Try again in 30s').kind === 'banned'
);

// --- 轮询策略：鉴权失败必须停表，抖动才退避 ---------------------------------
check('banned stops auto refresh', A.pollDecision('banned', 5).action === 'stop');
check('invalid_key stops auto refresh', A.pollDecision('invalid_key', 1).action === 'stop');
equal('server failure backs off 30s', A.pollDecision('server', 1).delayMs, 30000);
equal('second server failure backs off 60s', A.pollDecision('server', 2).delayMs, 60000);
equal('third server failure backs off 120s', A.pollDecision('server', 3).delayMs, 120000);
equal('backoff is capped', A.pollDecision('network', 9).delayMs, 120000);
equal('business failure keeps normal cadence', A.pollDecision('business', 1).delayMs, A.AUTO_REFRESH_MS);

if (failed > 0) {
  console.log('failed: ' + failed);
  process.exit(1);
}
console.log('all ui_auth behaviour checks passed');
