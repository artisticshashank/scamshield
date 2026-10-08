export type PendingScan = {
  request_id: string;
  input: string;
  input_type: "url" | "message";
  return_to: string;
};

const KEY = "scamshield.pending_scan";

export function savePendingScan(scan: PendingScan): void {
  sessionStorage.setItem(KEY, JSON.stringify(scan));
}

export function readPendingScan(): PendingScan | null {
  const raw = sessionStorage.getItem(KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as PendingScan;
  } catch {
    sessionStorage.removeItem(KEY);
    return null;
  }
}

export function clearPendingScan(): void {
  sessionStorage.removeItem(KEY);
}
