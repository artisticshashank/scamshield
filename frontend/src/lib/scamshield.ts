export type ScanRecord = {
  scan_id?: string;
  input_type: string;
  original_input: string;
  normalized_urls?: Array<Record<string, unknown>>;
  verdict: string;
  risk_score: number;
  recommendation: string;
  rule_result?: Record<string, unknown>;
  ml_result?: Record<string, unknown>;
  shap_result?: Record<string, unknown>;
  reputation_result?: Record<string, unknown>;
  domain_intelligence_result?: Record<string, unknown>;
  redirect_result?: Record<string, unknown>;
  triggered_rules?: Array<Record<string, unknown>>;
  evidence?: Array<Record<string, unknown>>;
  score_breakdown?: {
    final_score?: number;
    rule_score?: number | null;
    ml_score?: number | null;
    reputation_score?: number | null;
    domain_intelligence_score?: number | null;
    redirect_score?: number | null;
    weighted_contributions?: Record<string, number>;
    unavailable_signals?: string[];
  };
  timestamp?: string;
  metadata?: Record<string, unknown>;
};

export type MessageScanRecord = {
  input_type: "message";
  original_message: string;
  extracted_urls: string[];
  scan_results: ScanRecord[];
  overall_verdict: string;
  overall_risk_score: number | null;
  recommendation: string;
  metadata?: Record<string, unknown>;
};

export type ScanResponse = ScanRecord | MessageScanRecord;
type StoredScan = { id: string; response: ScanResponse; saved_at: string };

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_SCAMSHIELD_API_URL ?? "http://localhost:8000";

export function isMessageScan(
  response: ScanResponse,
): response is MessageScanRecord {
  return response.input_type === "message";
}

export function primaryScan(response: ScanResponse): ScanRecord | null {
  if (!isMessageScan(response)) return response;
  const severity: Record<string, number> = {
    SAFE: 0,
    SUSPICIOUS: 1,
    DANGEROUS: 2,
  };
  return response.scan_results.reduce<ScanRecord | null>((highest, current) => {
    if (!highest) return current;
    const currentKey = [current.risk_score, severity[current.verdict.toUpperCase()] ?? -1];
    const highestKey = [highest.risk_score, severity[highest.verdict.toUpperCase()] ?? -1];
    return currentKey[0] > highestKey[0] ||
      (currentKey[0] === highestKey[0] && currentKey[1] > highestKey[1])
      ? current
      : highest;
  }, null);
}

export function saveScan(response: ScanResponse): void {
  const records = isMessageScan(response) ? response.scan_results : [response];
  const stored: StoredScan[] = records
    .filter((record) => Boolean(record.scan_id))
    .map((record) => ({
      id: record.scan_id as string,
      response: record,
      saved_at: new Date().toISOString(),
    }));
  const item = {
    id: responseId(response),
    response,
    saved_at: new Date().toISOString(),
  };
  const existing = JSON.parse(
    window.localStorage.getItem("scamshield.scan_history") ?? "[]",
  ) as StoredScan[];
  window.localStorage.setItem(
    "scamshield.scan_history",
    JSON.stringify([item, ...existing].slice(0, 100)),
  );
  const scanRecords = JSON.parse(
    window.localStorage.getItem("scamshield.scan_records") ?? "[]",
  ) as StoredScan[];
  const byId = new Map(
    [...scanRecords, ...stored].map((record) => [record.id, record]),
  );
  window.localStorage.setItem(
    "scamshield.scan_records",
    JSON.stringify([...byId.values()].slice(-100)),
  );
  window.sessionStorage.setItem("scamshield.latest_scan", JSON.stringify(response));
}

export function responseId(response: ScanResponse): string {
  if (isMessageScan(response)) {
    return response.scan_results[0]?.scan_id ?? crypto.randomUUID();
  }
  return response.scan_id ?? crypto.randomUUID();
}

export function selectScan(scanId: string): string {
  return `/forensics?scan_id=${encodeURIComponent(scanId)}`;
}

export function readScanById(scanId: string): ScanResponse | null {
  if (!scanId) return null;
  const raw = window.localStorage.getItem("scamshield.scan_records");
  if (!raw) return null;
  const records = JSON.parse(raw) as StoredScan[];
  return records.find((record) => record.id === scanId)?.response ?? null;
}

export function readSelectedScan(): ScanResponse | null {
  const scanId = new URLSearchParams(window.location.search).get("scan_id");
  return scanId ? readScanById(scanId) : readLatestScan();
}

export function readLatestScan(): ScanResponse | null {
  const raw = window.sessionStorage.getItem("scamshield.latest_scan");
  return raw ? (JSON.parse(raw) as ScanResponse) : null;
}

export function formatVerdict(value: string): string {
  return value.replaceAll("_", " ").toUpperCase();
}
