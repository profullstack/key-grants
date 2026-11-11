export declare const MANIFEST_PATH: '/.well-known/logicsrc-grant/';
export declare const DEFAULT_WEBHOOK_PATH: '/api/v1/logicsrc/webhook';
export declare const DEFAULT_LOGICSRC_URL: 'https://app.logicsrc.com';
export declare const RECIPIENT_FORMAT: 'sealed-secrets/inbox-v2';
export declare const SEALED_PREFIX: 'sealed:v2:';

export declare class KeyGrantError extends Error {
  code: 'signed_out' | 'needs_vault' | 'no_keys' | 'too_many' | 'bad_key' | string;
  status: number;
}

export interface Recipient {
  app: string;
  scope: string;
  user_id: string;
  inbox_public_key: string;
}

export interface GrantRequestRow {
  nonce: string;
  user_id: string;
  scope: string | null;
  keys: string;
  webhook_secret: string;
  next_path: string;
  created_at: number;
  expires_at: number;
}

export interface GrantRow {
  grant_id: string;
  nonce: string;
  user_id: string;
  scope: string | null;
  key_name: string;
  status: 'active' | 'revoked';
  updated_at: number;
}

export interface KeyGrantStore {
  saveRequest(row: GrantRequestRow): Promise<void>;
  getRequest(nonce: string): Promise<GrantRequestRow | null>;
  requestsForUser(userId: string, limit: number): Promise<GrantRequestRow[]>;
  getGrant(grantId: string): Promise<GrantRow | null>;
  saveGrant(row: GrantRow): Promise<void>;
}

export interface KeyEvent {
  userId: string;
  scope: string | null;
  keyName: string;
  grantId: string;
}

export interface KeyGrantsOptions {
  appName: string;
  origin: string;
  store: KeyGrantStore;
  recipientFor(userId: string): Promise<Recipient | null>;
  onKey(e: KeyEvent & { sealed: string; type: 'grant.delivered' | 'grant.updated' }): Promise<void>;
  onRevoke?(e: KeyEvent): Promise<void>;
  logicsrcUrl?: string;
  webhookPath?: string;
  ttlMs?: number;
  describeKey?(name: string): string;
  now?(): number;
}

export interface Manifest {
  v: 1;
  app_name: string;
  keys: Array<{ name: string; description: string }>;
  recipient: Recipient & { format: 'sealed-secrets/inbox-v2' };
  webhook_url: string;
  webhook_secret: string;
  return_url: string;
  expires_at: number;
}

export interface KeyGrants {
  start(o: { userId: string; keys: string | string[]; next?: string; scope?: string | null }): Promise<string>;
  manifest(nonce: string): Promise<Manifest | null>;
  webhook(headers: Headers | Record<string, string | string[] | undefined>, rawBody: string): Promise<{ status: number; body: Record<string, unknown> }>;
  startResponse(o: { userId: string; keys: string | string[]; next?: string; scope?: string | null; errorPath?: string }): Promise<Response>;
  manifestResponse(nonce: string): Promise<Response>;
  webhookResponse(request: Request): Promise<Response>;
  origin: string;
  logicsrcUrl: string;
  webhookPath: string;
}

export declare function createKeyGrants(o: KeyGrantsOptions): KeyGrants;
export declare function parseKeyNames(input: string | string[]): string[];
export declare function verifyWebhook(
  secret: string,
  headers: Headers | Record<string, string | string[] | undefined>,
  body: string,
  opts?: { now?: number; tolerance?: number },
): boolean;
export declare function memoryStore(): KeyGrantStore & { requests: Map<string, GrantRequestRow>; grants: Map<string, GrantRow> };
export declare function sqlStore(
  client: { query(sql: string, params: unknown[]): Promise<object[]> },
  opts?: { placeholder?: '?' | '$'; prefix?: string },
): KeyGrantStore & { ensure(): Promise<void> };
