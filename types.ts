// Interface for creating or updating an SHL
// aside from userId, represents the user-defined SHL fields
export interface HealthLinkConfig {
  passcode?: string;
  exp?: number;
  label?: string;
}

// Internal SHL representation including internal access criteria
export interface HealthLink {
  config: HealthLinkConfig;
  active: boolean;
  id: string;
  managementToken: string;
  passcodeFailuresRemaining: number;
}

// Public SHL content exposed via "/shlink:" url
export interface SHLDecoded {
  id: string;
  url: string;
  flag: string;
  key: string & { length: 43 };
  exp?: number;
  label?: string;
  v?: number;
}

// File properties (no content)
export interface FileSummary {
  label?: string;
  added: string;
  contentType: string;
  contentHash: string;
}

// All data relating to an SHL, including public fields, internal access criteria, and files
export interface HealthLinkFull extends SHLDecoded, Omit<HealthLink, 'passcodeFailuresRemaining' | 'active'> {
  files: FileSummary[];
}

// HealthLinkFull without config, and with passcode
export interface HealthLinkFullFlat extends Omit<HealthLinkFull, 'config'>, Pick<HealthLinkConfig, 'passcode'> {}

// Entry in SHL manifest, can be file or endpoint
export interface SHLinkManifestEntry {
  contentType: 'application/fhir+json' | 'application/smart-health-card' | 'application/smart-api-access';
  embedded?: string;
  location: string;
}

// HealthLink file interface (add and retrieve for manifest)
export interface HealthLinkFileContent {
  contentType: string;
  hash?: string;
  content: Uint8Array<ArrayBuffer>;
}

// HealthLink endpoint interface (add and retrieve for manifest)
export interface HealthLinkEndpointContent {
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

// SHL Manifest
export interface SHLinkManifest {
  files: SHLinkManifestEntry[];
}

// Input type for retrieving SHL manifest
export interface HealthLinkManifestRequest {
  recipient: string;
  passcode?: string;
  embeddedLengthMax?: number;
}

/** Database table result types */
export interface cas_item {
  content_hash: string;
  content: Uint8Array<ArrayBuffer>;
  content_type: string;
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
