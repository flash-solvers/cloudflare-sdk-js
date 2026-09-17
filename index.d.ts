export const DEFAULT_ENDPOINT: string;
export const DEFAULT_USER_AGENT: string;
export const DEFAULT_MAX_ATTEMPTS: number;
export const CLEARANCE_COOKIE: string;
export const LIB_VERSION: string;
export const TLS_PROFILE: string;

export interface SolverOptions {
  /** Your Flash Solvers API key. */
  apiKey: string;
  /** http://, https:// or socks5:// proxy URL used for every request to the site. */
  proxy?: string | null;
  /** Defaults to DEFAULT_ENDPOINT. */
  endpoint?: string;
  /** Defaults to DEFAULT_USER_AGENT and must match the API's browser profile. */
  userAgent?: string;
  /** Solves to start before giving up. Defaults to 3. */
  maxAttempts?: number;
  /** Timeout for each Flash Solvers API call. Defaults to 60000. */
  apiTimeoutMs?: number;
}

export interface SolveResult {
  /** The cf_clearance cookie value. */
  clearance: string;
  /** All cookies for the solved URL, including cf_clearance. */
  cookies: Record<string, string>;
  /** Send this user agent with the cookies, through the same proxy. */
  userAgent: string;
  /** How many solves were started. */
  attempts: number;
}

export class CloudflareSolver {
  constructor(options: SolverOptions);
  /** Clears the Cloudflare challenge on url. */
  solve(url: string): Promise<SolveResult>;
}

export class CloudflareError extends Error {
  retrySafe?: boolean;
}

export class APIError extends CloudflareError {
  status: number;
  code: string;
  retrySafe: boolean;
  requestId: string | null;
  retryAfterMs: number;
}

export class SolveError extends CloudflareError {
  kind: string;
  owner: string | null;
  retrySafe: boolean;
}

export class NotClearedError extends CloudflareError {}

export class TLSError extends Error {}

export interface TLSResponse {
  status: number;
  headers: Record<string, string[]>;
  body: Buffer;
}

export class TLSSession {
  constructor(proxy?: string | null);
  id: string;
  request(options: {
    method: string;
    url: string;
    headers: Record<string, string>;
    headerOrder: string[];
    body?: string | null;
    host?: string;
    timeoutMs?: number;
  }): Promise<TLSResponse>;
  cookies(url: string): Promise<Array<{ name: string; value: string; domain: string; path: string }>>;
  addCookies(url: string, cookies: Array<{ name: string; value: string; path?: string; secure?: boolean; expires?: number }>): Promise<void>;
  close(): Promise<void>;
}
