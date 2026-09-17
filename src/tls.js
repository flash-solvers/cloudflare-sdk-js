'use strict';

// Chrome TLS sessions through bogdanfinn/tls-client's official shared library.
// The library is downloaded once per machine from its GitHub release and checked
// against a pinned SHA-256 before it is loaded.

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const koffi = require('koffi');

const LIB_VERSION = '1.16.0';
const TLS_PROFILE = 'chrome_152';
const RELEASE_URL = `https://github.com/bogdanfinn/tls-client/releases/download/v${LIB_VERSION}/`;

// [file name, sha256] per platform.
const ASSETS = {
  'win32-x64': ['tls-client-windows-64-1.16.0.dll', '53dca636b32d965ee6fe4562f39df959b2063febaa3d740efa925d1873cf11d7'],
  'win32-ia32': ['tls-client-windows-32-1.16.0.dll', '5203a36f80ea3f9cdfa43bf072a775702d1802acb8e4304e78905210f67dd2af'],
  'linux-x64': ['tls-client-linux-ubuntu-amd64-1.16.0.so', '2ec853496634545e7a7ea028715763948d55bbdd97aca7ecaa9fea8c2ebb08df'],
  'linux-musl-x64': ['tls-client-linux-alpine-amd64-1.16.0.so', '83c8702e8e8af2e5629277f422e77384a8780ac63c7f20988269a82d78e835ae'],
  'linux-arm64': ['tls-client-linux-arm64-1.16.0.so', 'e398622f99c0ce8fccb50ff6e414f373b5932a0277ece90468a796992f0ae518'],
  'linux-arm': ['tls-client-linux-armv7-1.16.0.so', '22baa029d4ee8cf327d10cda0e66c29cf256b3eb48e1fe9d6a76954b66f77711'],
  'darwin-x64': ['tls-client-darwin-amd64-1.16.0.dylib', '6463457ea713a96b3b8c94fd9d8746e7bc510cb6784fcf0f4bb64d9c83e3251a'],
  'darwin-arm64': ['tls-client-darwin-arm64-1.16.0.dylib', '99984d013921c753ab29d28720cb099eff6adf63538347e13652cb5cfe5bdc02'],
};

class TLSError extends Error {
  constructor(message) {
    super(message);
    this.name = 'TLSError';
  }
}

function platformKey() {
  if (process.platform === 'linux' && process.arch === 'x64' && fs.existsSync('/etc/alpine-release')) {
    return 'linux-musl-x64';
  }
  return `${process.platform}-${process.arch}`;
}

function cacheDir() {
  const base = process.platform === 'win32'
    ? (process.env.LOCALAPPDATA || os.homedir())
    : (process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache'));
  return path.join(base, 'flashsolvers', 'tls-client');
}

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

async function libraryPath() {
  if (process.env.FLASH_TLS_LIB) return process.env.FLASH_TLS_LIB;
  const key = platformKey();
  const asset = ASSETS[key];
  if (!asset) throw new TLSError(`no tls-client build for platform ${key}; set FLASH_TLS_LIB to a library path`);
  const [name, want] = asset;
  const file = path.join(cacheDir(), name);
  if (fs.existsSync(file) && sha256(file) === want) return file;

  fs.mkdirSync(path.dirname(file), { recursive: true });
  const res = await fetch(RELEASE_URL + name);
  if (!res.ok) throw new TLSError(`download ${name}: HTTP ${res.status}`);
  const bytes = Buffer.from(await res.arrayBuffer());
  const got = crypto.createHash('sha256').update(bytes).digest('hex');
  if (got !== want) throw new TLSError(`tls-client download checksum mismatch: got ${got}, want ${want}`);
  const tmp = `${file}.${process.pid}.${Date.now()}.part`;
  fs.writeFileSync(tmp, bytes);
  fs.renameSync(tmp, file);
  return file;
}

let loading = null;

function load() {
  if (!loading) {
    loading = libraryPath().then((file) => {
      const lib = koffi.load(file);
      return {
        request: lib.func('const char* request(const char* params)'),
        getCookiesFromSession: lib.func('const char* getCookiesFromSession(const char* params)'),
        addCookiesToSession: lib.func('const char* addCookiesToSession(const char* params)'),
        destroySession: lib.func('const char* destroySession(const char* params)'),
        freeMemory: lib.func('void freeMemory(const char* id)'),
      };
    });
    loading.catch(() => { loading = null; });
  }
  return loading;
}

async function call(fn, payload) {
  const lib = await load();
  // Run on koffi's worker pool so a slow request never blocks the event loop.
  const raw = await new Promise((resolve, reject) => {
    lib[fn].async(JSON.stringify(payload), (err, res) => (err ? reject(err) : resolve(res)));
  });
  const out = JSON.parse(raw);
  if (out.id) lib.freeMemory(out.id);
  return out;
}

class TLSSession {
  /** One browser session: a TLS client, a cookie jar and an optional proxy. */
  constructor(proxy) {
    this.id = crypto.randomUUID();
    this.proxy = proxy || null;
  }

  /** Resolves to { status, headers: {name: [values]}, body: Buffer }. Rejects with TLSError when there is no HTTP response. */
  async request({ method, url, headers, headerOrder, body, host, timeoutMs }) {
    const payload = {
      sessionId: this.id,
      tlsClientIdentifier: TLS_PROFILE,
      withRandomTLSExtensionOrder: true,
      followRedirects: false,
      disableHttp3: true,
      isByteResponse: true,
      catchPanics: true,
      requestMethod: method,
      requestUrl: url,
      headers,
      headerOrder,
      timeoutMilliseconds: timeoutMs || 60000,
    };
    if (body) payload.requestBody = body;
    if (host) payload.requestHostOverride = host;
    if (this.proxy) payload.proxyUrl = this.proxy;
    const out = await call('request', payload);
    if (!out.status) throw new TLSError(out.body || 'request failed');
    const data = out.body || '';
    const comma = data.indexOf(',');
    const content = data.startsWith('data:') && comma >= 0 ? Buffer.from(data.slice(comma + 1), 'base64') : Buffer.alloc(0);
    return { status: out.status, headers: out.headers || {}, body: content };
  }

  /** Resolves to the jar's cookies for url. */
  async cookies(url) {
    const out = await call('getCookiesFromSession', { sessionId: this.id, url });
    if ('status' in out) throw new TLSError(out.body || 'get cookies failed');
    return out.cookies || [];
  }

  async addCookies(url, cookies) {
    const out = await call('addCookiesToSession', { sessionId: this.id, url, cookies });
    if ('status' in out) throw new TLSError(out.body || 'add cookies failed');
  }

  async close() {
    await call('destroySession', { sessionId: this.id });
  }
}

module.exports = { TLSSession, TLSError, LIB_VERSION, TLS_PROFILE };
