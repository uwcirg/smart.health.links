export interface HealthLinkFile {
  contentType: string;
  content: Uint8Array;
}

export interface HealthLinkEndpoint {
  id?: string;
  refreshTime?: string;
  endpointUrl: string;
  config: {
    key: string;
    clientId: string;
    clientSecret: string;
    tokenEndpoint: string;
    refreshToken: string;
  };
  accessTokenResponse?: {
    access_token: string;
    scope: string;
    refresh_token?: string;
  };
}

export interface HealthLinkConfig {
  userId?: string;
  passcode?: string;
  exp?: number;
  label?: string;
}

export interface HealthLink {
  config: HealthLinkConfig;
  active: boolean;
  id: string;
  managementToken: string;
  passcodeFailuresRemaining: number;
}

export interface HealthLinkFull extends SHLDecoded, Omit<HealthLink, 'passcodeFailuresRemaining' | 'active'> {
  files: FileSummary[];
}

export interface HealthLinkFullReturn extends Omit<HealthLinkFull, 'config'> {
  config?: HealthLinkConfig;
}

export interface HealthLinkManifestRequest {
  recipient: string;
  passcode?: string;
  embeddedLengthMax?: number;
}

export interface FileSummary {
  label?: string;
  added: string;
  contentType: string;
  contentHash: string;
}

export interface SHLinkManifestFile {
  contentType: 'application/fhir+json' | 'application/smart-health-card' | 'application/smart-api-access';
  location: string;
}

export interface SHLinkManifest {
  files: SHLinkManifestFile[];
}

export interface SHLinkAddFileRequest {
  id: string;
  files: HealthLinkFile[];
}

export interface SHLDecoded {
  id: string;
  url: string;
  flag: string;
  key: string & { length: 43 };
  exp?: number;
  label?: string;
  v?: number;
}

/** Database table result types */
export interface cas_item {
  hash?: string;
  content?: Uint8Array;
  content_type?: string;
}
export interface user {
  id?: string;
}
export interface user_shlink {
  user?: string;
  shlink?: string;
}
export interface shlink_access {
  id?: string;
  active?: number;
  config_exp?: number;
  config_passcode?: string;
  management_token?: string;
  passcode_failures_remaining?: number;
}
export interface shlink_public {
  shlink?: string;
  manifest_url?: string;
  flag?: string;
  encryption_key?: string & { length: 43 };
  label?: string;
  version?: number;
}
export interface shlink_file {
  shlink?: string;
  label?: string;
  added_time?: string;
  content_type?: string;
  content_hash?: string;
}
export interface shlink_endpoint {
  id?: string;
  shlink?: string;
  added_time?: string;
  endpoint_url?: string;
  config_key?: string;
  config_client_id?: string;
  config_client_secret?: string;
  config_token_endpoint?: string;
  config_refresh_token?: string;
  refresh_time?: string;
  access_token_response?: string;
}
export interface shlink_access_log {
  shlink?: string;
  recipient?: string;
  access_time?: string;
}

type Action = 'create' | 'read' | 'update' | 'delete' | 'execute' | 'login' | 'logout';
type Severity = 'critical' | 'error' | 'warning' | 'info' | 'debug';

export interface LogMessage {
  version: string;
  severity: Severity;
  action: Action;
  occurred?: string; // datetime of event
  subject?: string; // subject id
  agent?: {
    ip_address?: string;
    user_agent?: string | null;
    type?: string; // e.g. system, user
    who?: string; // agent id
  };
  source?: {
    observer?: string; // system url
    type?: string; // system/project name
    version?: string; // system version
  }
  entity?: {
    detail?: {[key: string] : string}; // additional info
    query?: string; // query parameters
  };
  outcome?: string; // failure or warning details
}

export interface LogMessageSimple extends Partial<LogMessage> {
  action: Action;
}
