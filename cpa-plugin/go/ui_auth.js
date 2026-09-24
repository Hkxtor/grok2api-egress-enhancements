/* ui_auth.js — 管理密钥解析 / 管理 API 失败分类 / 自动刷新策略
 *
 * 纯函数模块（不碰 DOM），同源插件资源页与 Node 行为测试共用同一份实现。
 *
 * 背景：CPA 的管理路由（包含插件自己的 /v0/management/... 路由）在鉴权层按客户端 IP
 * 计数失败次数，连续 5 次失败会临时封禁该 IP 约 30 分钟，且封禁期间即使密钥正确也会被拒。
 * 本机部署时浏览器与管理面板共用同一个 IP，所以“用错密钥反复轮询”会直接锁死管理面板。
 * 因此这里的原则是：宁可认定为“没有可用密钥”，也不把不确定的值当密钥发出去；
 * 一旦确认是鉴权失败，必须立刻停止轮询。
 */
(function (global) {
  'use strict';

  const ENC_PREFIX = 'enc::v1::';
  const SECRET_SALT = 'cli-proxy-api-webui::secure-storage';
  const MAX_KEY_LENGTH = 512;

  // 管理中心（Cli-Proxy-API-Management-Center）持久化认证状态的 localStorage key。
  // 这份列表刻意保持克制：历史版本曾猜测 authToken 之类的键名，
  // 而面板从未写过 authToken，命中它等于拿着一个非密钥值反复请求。
  const AUTH_STORAGE_KEYS = ['cli-proxy-auth'];
  // 旧版面板遗留的单值存储键（仅作为回退）。
  const LEGACY_STORAGE_KEYS = ['managementKey'];

  const AUTO_REFRESH_MS = 15000;
  const BACKOFF_MS = [30000, 60000, 120000];
  const HIDDEN_RECHECK_MS = 5000;

  function obfuscationSeed(host, userAgent) {
    return SECRET_SALT + '|' + String(host == null ? '' : host) + '|' + String(userAgent == null ? '' : userAgent);
  }

  function encodeText(text) {
    return new TextEncoder().encode(text);
  }

  function decodeText(bytes) {
    return new TextDecoder().decode(bytes);
  }

  // 与管理中心 src/utils/encryption.ts 的可逆混淆保持一致；
  // 解不开就返回空串，绝不能把密文本身当成密钥发送。
  function deobfuscate(payload, host, userAgent) {
    const raw = String(payload == null ? '' : payload);
    if (raw.indexOf(ENC_PREFIX) !== 0) return raw;
    try {
      const binary = global.atob(raw.slice(ENC_PREFIX.length));
      const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
      const seed = encodeText(obfuscationSeed(host, userAgent));
      for (let index = 0; index < bytes.length; index += 1) {
        bytes[index] ^= seed[index % seed.length];
      }
      return decodeText(bytes);
    } catch (_) {
      return '';
    }
  }

  function tryParseJSON(text) {
    try {
      return JSON.parse(text);
    } catch (_) {
      return undefined;
    }
  }

  // Zustand persist 的载荷可能是对象，也可能被多包了一层/两层 JSON 字符串
  // （不同面板版本对 createJSONStorage 的包装方式不同）。
  // 最多剥三层字符串，剥出对象即返回；其它情况一律视为“读不懂”。
  function unwrapPersisted(raw) {
    let value = String(raw == null ? '' : raw);
    for (let depth = 0; depth < 3; depth += 1) {
      const parsed = tryParseJSON(value);
      if (parsed === undefined) return null;
      if (typeof parsed === 'string') {
        value = parsed;
        continue;
      }
      if (parsed && typeof parsed === 'object') return parsed;
      return null;
    }
    return null;
  }

  // 管理密钥一定是单行纯文本。JSON 片段、换行、控制字符、超长值都是误读。
  function looksLikeManagementKey(value) {
    const key = String(value == null ? '' : value).trim();
    if (!key || key.length > MAX_KEY_LENGTH) return false;
    if (/[\s\u0000-\u001f\u007f]/.test(key)) return false;
    const head = key.charAt(0);
    if (head === '{' || head === '[' || head === '"') return false;
    return true;
  }

  function firstManagementKey(candidates) {
    for (let index = 0; index < candidates.length; index += 1) {
      const candidate = candidates[index];
      if (looksLikeManagementKey(candidate)) return String(candidate).trim();
    }
    return '';
  }

  // cli-proxy-auth 的形态：{"state":{"managementKey":"..."},"version":0}
  function keyFromAuthStore(payload, host, userAgent) {
    const store = unwrapPersisted(deobfuscate(payload, host, userAgent));
    if (!store) return '';
    return firstManagementKey([
      store.state && store.state.managementKey,
      store.managementKey
    ]);
  }

  // 旧版单值存储：可能是裸密钥、JSON 字符串或带包一层对象的值。
  function keyFromLegacyValue(payload, host, userAgent) {
    const text = deobfuscate(payload, host, userAgent);
    const store = unwrapPersisted(text);
    if (!store) return firstManagementKey([text]);
    return firstManagementKey([
      store.state && store.state.managementKey,
      store.managementKey,
      store.value,
      store.token
    ]);
  }

  // 解析顺序：官方 cli-proxy-auth（唯一权威）→ 旧版遗留单值键。
  // 官方条目存在且能读懂时它就是权威：即使里面没有密钥（未勾「记住密码」），
  // 也不再回退到可能是陈年旧值的遗留键；只有官方条目缺失/读不懂时才回退。
  function resolveManagementKey(storage, host, userAgent) {
    if (!storage || typeof storage.getItem !== 'function') return '';
    for (let index = 0; index < AUTH_STORAGE_KEYS.length; index += 1) {
      const raw = storage.getItem(AUTH_STORAGE_KEYS[index]);
      if (!raw) continue;
      const key = keyFromAuthStore(raw, host, userAgent);
      if (key) return key;
      if (unwrapPersisted(deobfuscate(raw, host, userAgent))) return '';
    }
    for (let index = 0; index < LEGACY_STORAGE_KEYS.length; index += 1) {
      const raw = storage.getItem(LEGACY_STORAGE_KEYS[index]);
      if (!raw) continue;
      const key = keyFromLegacyValue(raw, host, userAgent);
      if (key) return key;
    }
    return '';
  }

  // CPA 管理鉴权层的失败响应（插件路由同样先过这一层）：
  //   401 {"error":"missing management key"}
  //   401 {"error":"invalid management key"}
  //   403 {"error":"IP banned due to too many failed attempts. Try again in 14m49s"}
  // 注意：插件业务自己也会返回 403（例如缺少 UI 标记头），
  // 所以只看状态码会把业务 403 误判成密钥问题，必须优先按消息判定。
  function classifyFailure(status, body) {
    const code = Number(status) || 0;
    const rawText = String(body == null ? '' : body);
    let message = rawText.trim();
    const parsed = tryParseJSON(rawText);
    if (parsed && typeof parsed === 'object') {
      if (typeof parsed.error === 'string') message = parsed.error;
      else if (parsed.error && typeof parsed.error.message === 'string') message = parsed.error.message;
      else if (typeof parsed.message === 'string') message = parsed.message;
    }
    const lower = message.toLowerCase();
    const banned = lower.indexOf('ip banned') >= 0 || lower.indexOf('too many failed attempts') >= 0;
    let retrySeconds = 0;
    if (banned) {
      const match = /try again in\s*(?:(\d+)\s*m)?\s*(\d+)\s*s/i.exec(message);
      if (match) retrySeconds = Number(match[1] || 0) * 60 + Number(match[2] || 0);
    }

    let kind = 'business';
    if (banned) kind = 'banned';
    else if (code === 401 || lower.indexOf('invalid management key') >= 0 || lower.indexOf('missing management key') >= 0) kind = 'invalid_key';
    else if (code === 0) kind = 'network';
    else if (code >= 500) kind = 'server';

    return {
      kind: kind,
      status: code,
      message: message,
      retrySeconds: retrySeconds,
      auth: kind === 'banned' || kind === 'invalid_key'
    };
  }

  // 轮询策略：鉴权失败必须停止（继续轮询只会继续烧失败额度，把管理面板一起锁掉）；
  // 服务端/网络抖动才退避重试；业务错误维持常规刷新节奏。
  function pollDecision(kind, failureCount) {
    if (kind === 'banned' || kind === 'invalid_key') return { action: 'stop', delayMs: 0 };
    if (kind === 'server' || kind === 'network') {
      const attempt = Math.max(1, Number(failureCount) || 1);
      const index = Math.min(BACKOFF_MS.length - 1, attempt - 1);
      return { action: 'retry', delayMs: BACKOFF_MS[index] };
    }
    return { action: 'retry', delayMs: AUTO_REFRESH_MS };
  }

  global.EgressUIAuth = {
    ENC_PREFIX: ENC_PREFIX,
    SECRET_SALT: SECRET_SALT,
    MAX_KEY_LENGTH: MAX_KEY_LENGTH,
    AUTO_REFRESH_MS: AUTO_REFRESH_MS,
    BACKOFF_MS: BACKOFF_MS,
    HIDDEN_RECHECK_MS: HIDDEN_RECHECK_MS,
    AUTH_STORAGE_KEYS: AUTH_STORAGE_KEYS,
    LEGACY_STORAGE_KEYS: LEGACY_STORAGE_KEYS,
    obfuscationSeed: obfuscationSeed,
    deobfuscate: deobfuscate,
    unwrapPersisted: unwrapPersisted,
    looksLikeManagementKey: looksLikeManagementKey,
    keyFromAuthStore: keyFromAuthStore,
    keyFromLegacyValue: keyFromLegacyValue,
    resolveManagementKey: resolveManagementKey,
    classifyFailure: classifyFailure,
    pollDecision: pollDecision
  };
})(typeof window !== 'undefined' ? window : globalThis);
