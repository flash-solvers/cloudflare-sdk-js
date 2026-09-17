# Flash Solvers Cloudflare SDK for JavaScript

Solve the Cloudflare WAF challenge ("Just a moment...") with the [Flash Solvers](https://docs.flashsolvers.com/) API and get a `cf_clearance` cookie.

The API only generates each step of the challenge.
Every request to the protected site is made from your machine, with a Chrome 152 TLS fingerprint, your proxy and your cookie jar.

## Install

```sh
npm install github:flash-solvers/cloudflare-sdk-js
```

Requires Node.js 18.17 or newer. TypeScript types are included.

On first use the SDK downloads the official [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client) v1.16.0 shared library (about 20 MB) into your cache folder and checks its SHA-256.
Supported: Windows x64/x86, Linux x64/arm64/armv7 (glibc and Alpine), macOS x64/arm64.
To use a library you already have, set `FLASH_TLS_LIB` to its path.

## Usage

```js
const { CloudflareSolver } = require('@flash-solvers/cloudflare');
// or: import { CloudflareSolver } from '@flash-solvers/cloudflare';

const solver = new CloudflareSolver({
  apiKey: 'your-api-key',
  proxy: 'http://user:pass@host:port',
});

const result = await solver.solve('https://example.com/');
console.log('cf_clearance:', result.clearance);
console.log(result.cookies);   // all cookies for the solved URL
console.log(result.userAgent); // send this with the cookies
```

Use the cookies with the same proxy IP and `result.userAgent`, or Cloudflare will challenge you again.
Requests run on a native worker pool, so solves never block the event loop and can run concurrently.

## Options

| Option | Default | Description |
|---|---|---|
| `apiKey` | required | Your Flash Solvers API key |
| `proxy` | `null` | `http://`, `https://` or `socks5://` proxy for every request to the site |
| `maxAttempts` | `3` | Solves to start before giving up |
| `userAgent` | Chrome 152 on macOS | Must match the API's browser profile. Leave it unset |
| `endpoint` | `https://cf.flashsolvers.com` | API base URL |
| `apiTimeoutMs` | `60000` | Timeout per API call |

## Result

| Field | Description |
|---|---|
| `clearance` | The `cf_clearance` cookie value |
| `cookies` | Object of all cookies for the solved URL |
| `userAgent` | User agent to send with the cookies |
| `attempts` | How many solves were started |

## Errors

All errors except `TLSError` extend `CloudflareError`.

| Error | Cause | Retried |
|---|---|---|
| `APIError` with `code` `host_not_allowed` | The site is not supported | No |
| `APIError` with `code` `invalid_key`, `key_expired`, `insufficient_balance` | Key or balance problem | No |
| `APIError` with `code` `at_capacity` | Too many solves in flight | Yes, after `Retry-After` |
| `SolveError` | The solve failed. `kind` says why, such as `origin_refused` | When `retrySafe` |
| `NotClearedError` | Cloudflare did not accept any attempt | Each attempt is retried until `maxAttempts` |
| `TLSError` | The TLS library could not load or make a request | No |

Each retry uses a fresh session, because Cloudflare keeps rejecting a session that failed once.
A proxy IP that keeps failing is usually flagged; rotate it.

## Pricing

See the [Flash Solvers docs](https://docs.flashsolvers.com/#cloudflare-overview) for pricing and the full API reference.
You are charged once per solve that reaches the final form, never for failures.
