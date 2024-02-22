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
  passcode?: string;
  exp?: number;
}

export interface LTTInfo {
  patient_id: string;
  session_id: string;
}

export interface HealthLinkConfigLTT {
  config: HealthLinkConfig;
  ltt: LTTInfo;
}

export interface HealthLink {
  config: HealthLinkConfig;
  active: boolean;
  id: string;
  patient_id: string;
  session_id: string;
  created: string;
  managementToken: string;
  passcodeFailuresRemaining: number;
}

export interface HealthLinkManifestRequest {
  recipient: string;
  passcode?: string;
  embeddedLengthMax?: number;
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
}
