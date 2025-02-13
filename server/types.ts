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
  url: string;
  flag: string;
  key: string & { length: 43 };
  exp?: number;
  label?: string;
  v?: number;
}
