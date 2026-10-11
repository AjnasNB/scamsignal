export type Language = "en" | "hi";
export interface ScanReport {
  schema_version: 1;
  apk_sha256: string;
  file_size: number;
  package_name: string;
  version_name: string | null;
  version_code: number | null;
  app_name: string | null;
  signature: {
    status: "verified" | "invalid" | "unavailable";
    signer_sha256: string[];
    schemes: string[];
    errors: string[];
  };
  permissions: {
    name: string;
    category: "sensitive" | "standard";
    description_en: string;
    description_hi: string;
  }[];
  findings: {
    id: string;
    severity: "info" | "review" | "high";
    title_en: string;
    title_hi: string;
    evidence: string[];
    explanation_en: string;
    explanation_hi: string;
  }[];
  coverage: {
    manifest: boolean;
    signature: boolean;
    dex: boolean;
    notes: string[];
  };
  analyzed_at: string;
}
export interface PublicRecord {
  key: string;
  creator: string;
  expires_at?: string | number;
  [key: string]: unknown;
}
export interface ArkivResolution {
  status: "available" | "unavailable";
  passport: {
    status: "exact_match" | "signer_mismatch" | "unknown" | "incomplete";
    records: PublicRecord[];
  };
  warnings: PublicRecord[];
  ignored_count: number;
  error?: string;
}
export interface Example {
  id: string;
  label: string;
  context?: string;
  report: ScanReport;
}
