'use strict';

const { TLSSession, TLSError } = require('./tls');

const DEFAULT_ENDPOINT = 'https://cf.flashsolvers.com';
const DEFAULT_USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36';
const DEFAULT_MAX_ATTEMPTS = 3;
const CLEARANCE_COOKIE = 'cf_clearance';
const API_USER_AGENT = 'flashsolvers-cloudflare-js/0.1.0';

class CloudflareError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CloudflareError';
  }
}

/** A request the Flash Solvers API rejected, such as a bad key or an unsupported host. */
class APIError extends CloudflareError {
  constructor({ status, code, message, retrySafe = false, requestId = null, retryAfterMs = 0 }) {
    super(`api ${status} ${code}: ${message} (request ${requestId})`);
    this.name = 'APIError';
    Object.assign(this, { status, code, retrySafe, requestId, retryAfterMs });
  }
}

/** A solve the API ended with kind "error" or "aborted". */
class SolveError extends CloudflareError {
  constructor({ kind, owner = null, retrySafe = false }) {
    super(`solve failed: ${kind} (owner ${owner}, retrySafe ${retrySafe})`);
    this.name = 'SolveError';
    Object.assign(this, { kind, owner, retrySafe });
  }
}

/** Every attempt finished without a cf_clearance cookie. */
class NotClearedError extends CloudflareError {
  constructor() {
    super('challenge not cleared');
    this.name = 'NotClearedError';
    this.retrySafe = true;
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Solves the Cloudflare WAF challenge with the Flash Solvers API.
 *
 * The API only generates each step. Every request to the protected site is made
 * from this process, with a Chrome TLS fingerprint, your proxy and a fresh cookie jar.
 */
class CloudflareSolver {
  constructor({ apiKey, proxy = null, endpoint = DEFAULT_ENDPOINT, userAgent = DEFAULT_USER_AGENT,
    maxAttempts = DEFAULT_MAX_ATTEMPTS, apiTimeoutMs = 60000 } = {}) {
    if (!apiKey) throw new TypeError('apiKey is required');
    this.apiKey = apiKey;
    this.proxy = proxy;
    this.endpoint = endpoint.replace(/\/+$/, '');
    this.userAgent = userAgent;
    this.maxAttempts = Math.max(1, maxAttempts | 0);
    this.apiTimeoutMs = apiTimeoutMs;
  }

  /** Clears the challenge on url. Resolves to { clearance, cookies, userAgent, attempts }. */
  async solve(url) {
    let last = new NotClearedError();
    for (let attempt = 1; attempt <= this.maxAttempts; attempt++) {
      // A failed attempt taints its session, so every attempt starts a new one.
      const session = new TLSSession(this.proxy);
      let outcome;
      try {
        outcome = await this.attempt(session, url);
        if (outcome.clearance) {
          const cookies = {};
          for (const c of await session.cookies(url).catch(() => [])) cookies[c.name] = c.value;
          cookies[CLEARANCE_COOKIE] = outcome.clearance;
          return { clearance: outcome.clearance, cookies, userAgent: this.userAgent, attempts: attempt };
        }
      } finally {
        await session.close().catch(() => {});
      }
      if (outcome.error) {
        last = outcome.error;
        if (!outcome.error.retrySafe) throw outcome.error;
      }
      if (attempt < this.maxAttempts && outcome.waitMs > 0) await sleep(outcome.waitMs);
    }
    throw last;
  }

  /** Runs one solve. Resolves to { clearance } or { error, waitMs }. */
  async attempt(session, url) {
    let out;
    try {
      out = await this.call({
        start: { url, userAgent: this.userAgent, finishAtForm: true, clientPacingV1: true, clientJarWritesV1: true },
      });
    } catch (e) {
      if (e instanceof APIError) return { error: e, waitMs: e.retryAfterMs };
      throw e;
    }
    for (;;) {
      switch (out.kind) {
        case 'request': {
          const response = await perform(session, out);
          try {
            out = await this.call({ context: out.context, sequence: out.sequence, response });
          } catch (e) {
            if (e instanceof APIError) return { error: e, waitMs: e.retryAfterMs };
            throw e;
          }
          break;
        }
        case 'final': {
          const response = await perform(session, out);
          if (response.error) {
            const error = new CloudflareError(`form POST: ${response.error}`);
            error.retrySafe = true;
            return { error, waitMs: 0 };
          }
          if (response.headers.some((h) => h.name.toLowerCase() === 'cf-mitigated')) {
            return { error: new NotClearedError(), waitMs: 0 };
          }
          return { clearance: clearanceFrom(await session.cookies(out.payloadUrl)) };
        }
        case 'complete': {
          const result = out.result || {};
          if (result.outcome === 'cleared') {
            return { clearance: result.clearance || clearanceFrom(await session.cookies(url)) };
          }
          return { error: new NotClearedError(), waitMs: nextWait(out) };
        }
        case 'error':
        case 'aborted': {
          const failure = out.failure || {};
          const error = new SolveError({
            kind: failure.kind || out.kind, owner: failure.owner || null,
            retrySafe: Boolean(failure.retrySafe) || Boolean(out.next),
          });
          return { error, waitMs: nextWait(out) };
        }
        default:
          throw new CloudflareError(`unexpected step kind ${JSON.stringify(out.kind)}`);
      }
    }
  }

  async call(body) {
    let res;
    try {
      res = await fetch(`${this.endpoint}/v1/step`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': this.apiKey, 'User-Agent': API_USER_AGENT },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(this.apiTimeoutMs),
      });
    } catch (e) {
      throw new CloudflareError(`api: ${e.message}`);
    }
    const raw = await res.text();
    if (res.ok) return JSON.parse(raw);
    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      data = { error: raw.trim() };
    }
    const retrySafe = Boolean(data.retrySafe) || res.status === 429;
    let retryAfterMs = 0;
    if (retrySafe) {
      const secs = parseInt(res.headers.get('retry-after') || '', 10);
      retryAfterMs = secs > 0 ? secs * 1000 : 1000;
    }
    throw new APIError({
      status: res.status, code: data.code, message: data.error, retrySafe, requestId: data.requestId, retryAfterMs,
    });
  }
}

/** Makes the origin request the API described and returns the step response. */
async function perform(session, step) {
  let pacingUs = 0;
  if (step.pacingMs > 0) {
    const started = process.hrtime.bigint();
    await sleep(step.pacingMs);
    pacingUs = Number((process.hrtime.bigint() - started) / 1000n);
  }
  if (step.setCookies && step.setCookies.length) {
    await session.addCookies(step.payloadUrl, step.setCookies.map(jarCookie));
  }
  const headers = {};
  for (const h of step.headers || []) headers[h.name] = h.value;
  const started = Date.now();
  let res;
  try {
    res = await session.request({
      method: step.method, url: step.payloadUrl, headers, headerOrder: step.headerOrder || [],
      body: step.payload || null, host: step.host, timeoutMs: step.timeoutMs,
    });
  } catch (e) {
    if (!(e instanceof TLSError)) throw e;
    return { error: e.message, timing: { durationMs: Date.now() - started, pacingUs } };
  }
  const elapsed = Date.now() - started;
  const response = {
    status: res.status,
    headers: Object.entries(res.headers).flatMap(([name, values]) => values.map((value) => ({ name, value }))),
    timing: { requestStartMs: 0, responseStartMs: elapsed, durationMs: elapsed, pacingUs },
  };
  const text = new TextDecoder('utf-8', { fatal: true });
  try {
    response.data = text.decode(res.body);
  } catch {
    response.dataBin = res.body.toString('base64');
  }
  const length = Object.entries(res.headers).find(([name]) => name.toLowerCase() === 'content-length');
  if (length && /^\d+$/.test(length[1][0] || '')) response.timing.wireBytes = Number(length[1][0]);
  return response;
}

function jarCookie(c) {
  const cookie = { name: c.name, value: c.value, secure: Boolean(c.secure) };
  if (c.path) cookie.path = c.path;
  if (c.expiresUnix > 0) cookie.expires = c.expiresUnix;
  return cookie;
}

function clearanceFrom(cookies) {
  const c = cookies.find((x) => x.name === CLEARANCE_COOKIE);
  return c ? c.value : null;
}

function nextWait(out) {
  return (out.next && out.next.retryAfterMs) || 0;
}

module.exports = {
  CloudflareSolver, CloudflareError, APIError, SolveError, NotClearedError,
  DEFAULT_ENDPOINT, DEFAULT_USER_AGENT, DEFAULT_MAX_ATTEMPTS, CLEARANCE_COOKIE,
};
