"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { AlertOctagon, CheckCircle, Clock, Copy, FileJson, Link2 } from "lucide-react";
import {
  formatVerdict,
  isMessageScan,
  primaryScan,
  readSelectedScan,
  type ScanRecord,
  type ScanResponse,
} from "@/lib/scamshield";

function score(value: unknown): string {
  return typeof value === "number" ? value.toFixed(1) : "N/A";
}

function statusClass(verdict: string): string {
  if (verdict === "DANGEROUS") return "bg-red-600 text-white";
  if (verdict === "SUSPICIOUS") return "bg-yellow-500 text-white";
  return "bg-green-600 text-white";
}

function SignalCard({
  name,
  signal,
}: {
  name: string;
  signal?: Record<string, unknown>;
}) {
  const status = typeof signal?.status === "string" ? signal.status : "unavailable";
  const signalScore = signal?.score;
  return (
    <div className="border border-gray-200 rounded-lg p-4 bg-white shadow-sm">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-bold text-gray-500 uppercase tracking-wider">{name}</span>
        <span className="text-xs font-mono text-gray-600">{status}</span>
      </div>
      <div className="text-2xl font-bold text-gray-900">
        {typeof signalScore === "number" ? score(signalScore) : "—"}
      </div>
    </div>
  );
}

export default function ForensicsPage() {
  const [response, setResponse] = useState<ScanResponse | null>(null);

  useEffect(() => {
    queueMicrotask(() => setResponse(readSelectedScan()));
  }, []);

  const scan = response ? primaryScan(response) : null;
  const message = response && isMessageScan(response) ? response : null;

  if (!scan && !message) {
    return (
      <div className="max-w-5xl mx-auto bg-white rounded-2xl border border-gray-200 p-8 space-y-4">
        <h1 className="text-3xl font-bold text-gray-900">Threat Forensics Report</h1>
        <p className="text-gray-600">No scan is loaded. Start a scan to view a backend-generated result.</p>
        <Link href="/" className="inline-block bg-gray-900 text-white px-4 py-2 rounded-lg font-bold">
          New scan
        </Link>
      </div>
    );
  }

  const displayed = scan ?? ({
    input_type: "message",
    original_input: message?.original_message ?? "",
    verdict: message?.overall_verdict ?? "safe",
    risk_score: message?.overall_risk_score ?? 0,
    recommendation: message?.recommendation ?? "",
  } as ScanRecord);
  const breakdown = displayed.score_breakdown;
  const rules = displayed.evidence ?? displayed.triggered_rules ?? [];
  const original = message?.original_message ?? displayed.original_input;

  return (
    <div className="max-w-[1200px] mx-auto space-y-8 pb-20">
      <header className="flex items-center justify-between border-b border-gray-200 pb-4">
        <div className="text-sm font-semibold text-gray-500 uppercase tracking-widest">
          <Link href="/history" className="hover:text-gray-900">SEC OPS</Link> /{" "}
          <span className="text-gray-900">Threat Forensics</span>
        </div>
        <Link href="/" className="text-sm font-bold text-gray-900 hover:text-blue-600">New scan</Link>
      </header>

      <section className="bg-white rounded-2xl border border-gray-200 shadow-sm p-8 space-y-8">
        <div className="flex items-start justify-between gap-6">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Threat Forensics Report</h1>
            <p className="text-sm text-gray-500 mt-2 flex items-center gap-2">
              <Clock className="w-4 h-4" /> {displayed.timestamp ?? "Backend result"} · {displayed.scan_id ?? "message scan"}
            </p>
          </div>
          <div className={`px-3 py-1.5 rounded text-xs font-bold uppercase tracking-wider ${statusClass(formatVerdict(displayed.verdict))}`}>
            {formatVerdict(displayed.verdict)}
          </div>
        </div>

        <div className="border border-gray-200 rounded-xl p-5 bg-gray-50">
          <div className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">
            {message ? "Scanned message" : "Analyzed URL"}
          </div>
          <code className="text-sm font-mono text-gray-900 break-all">{original}</code>
          {message && (
            <p className="text-sm text-gray-600 mt-3">
              Extracted URLs: {message.extracted_urls.length}
            </p>
          )}
        </div>

        {message && (
          <div>
            <h2 className="text-lg font-bold text-gray-900 border-b border-gray-200 pb-2 mb-4">
              Extracted URL results
            </h2>
            <div className="space-y-3">
              {message.scan_results.map((item, index) => (
                <div key={`${item.original_input}-${index}`} className="border border-gray-200 rounded-xl p-4">
                  <div className="flex items-center justify-between gap-4">
                    <code className="text-sm font-mono text-gray-900 break-all">{item.original_input}</code>
                    <span className={`shrink-0 px-2 py-1 rounded text-xs font-bold ${statusClass(formatVerdict(item.verdict))}`}>
                      {formatVerdict(item.verdict)}
                    </span>
                  </div>
                  <p className="text-sm text-gray-600 mt-2">
                    Risk score: {score(item.risk_score)} · {item.recommendation}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="bg-gray-50 border border-gray-200 rounded-xl p-6 flex items-center justify-between">
          <div>
            <div className="text-xs font-bold text-gray-500 uppercase tracking-wider">ScamShield risk score</div>
            <div className="text-5xl font-black text-gray-900">{score(displayed.risk_score)}<span className="text-xl text-gray-400">/100</span></div>
          </div>
          <p className="max-w-md text-sm text-gray-700">{displayed.recommendation}</p>
        </div>

        <div>
          <h2 className="text-lg font-bold text-gray-900 border-b border-gray-200 pb-2 mb-4">
            Signal fusion and availability
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <SignalCard name="Rules" signal={displayed.rule_result} />
            <SignalCard name="ML" signal={displayed.ml_result} />
            <SignalCard name="Reputation" signal={displayed.reputation_result} />
            <SignalCard name="Domain" signal={displayed.domain_intelligence_result} />
            <SignalCard name="Redirect" signal={displayed.redirect_result} />
            <SignalCard name="SHAP (explanatory)" signal={displayed.shap_result} />
          </div>
          {breakdown?.unavailable_signals && breakdown.unavailable_signals.length > 0 && (
            <p className="text-xs text-gray-500 mt-4">
              Unavailable signals: {breakdown.unavailable_signals.join(", ")}
            </p>
          )}
        </div>

        <div>
          <h2 className="text-lg font-bold text-gray-900 border-b border-gray-200 pb-2 mb-4">
            Rule evidence
          </h2>
          {rules.length ? (
            <div className="space-y-3">
              {rules.map((item, index) => (
                <div key={`${String(item.rule_id ?? item.feature ?? "evidence")}-${index}`} className="border border-gray-200 rounded-xl p-4">
                  <div className="flex justify-between gap-4">
                    <strong className="text-sm text-gray-900">{String(item.rule_id ?? item.category ?? "Evidence")}</strong>
                    <span className="text-xs font-mono text-gray-500">score {String(item.score ?? item.contribution ?? 0)}</span>
                  </div>
                  <p className="text-sm text-gray-600 mt-1">{String(item.explanation ?? "Triggered rule evidence")}</p>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-gray-500 flex items-center gap-2"><CheckCircle className="w-4 h-4" /> No positive rule evidence was triggered.</p>
          )}
        </div>

        <div>
          <h2 className="text-lg font-bold text-gray-900 border-b border-gray-200 pb-2 mb-4">Score breakdown</h2>
          <pre className="bg-gray-900 text-gray-100 rounded-xl p-4 text-xs overflow-auto">
            {JSON.stringify(breakdown ?? {}, null, 2)}
          </pre>
        </div>

        <div>
          <h2 className="text-lg font-bold text-gray-900 border-b border-gray-200 pb-2 mb-4">
            Backend evidence details
          </h2>
          <pre className="bg-gray-50 border border-gray-200 rounded-xl p-4 text-xs overflow-auto">
            {JSON.stringify({
              normalized_urls: displayed.normalized_urls ?? [],
              ml_result: displayed.ml_result ?? null,
              shap_result: displayed.shap_result ?? null,
              reputation_result: displayed.reputation_result ?? null,
              domain_intelligence_result: displayed.domain_intelligence_result ?? null,
              redirect_result: displayed.redirect_result ?? null,
              metadata: displayed.metadata ?? {},
            }, null, 2)}
          </pre>
        </div>

        <div className="flex flex-wrap gap-3">
          <button onClick={() => navigator.clipboard.writeText(original)} className="px-3 py-1.5 border border-gray-300 rounded text-sm font-medium flex items-center gap-2">
            <Copy className="w-4 h-4" /> Copy input
          </button>
          <button onClick={() => {
            const blob = new Blob([JSON.stringify(response, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const anchor = document.createElement("a");
            anchor.href = url;
            anchor.download = "scamshield-scan.json";
            anchor.click();
            URL.revokeObjectURL(url);
          }} className="px-3 py-1.5 border border-gray-300 rounded text-sm font-medium flex items-center gap-2">
            <FileJson className="w-4 h-4" /> Export JSON
          </button>
          <span className="px-3 py-1.5 text-sm text-gray-500 flex items-center gap-2"><Link2 className="w-4 h-4" /> No URL is opened by the UI</span>
          <span className="px-3 py-1.5 text-sm text-gray-500 flex items-center gap-2"><AlertOctagon className="w-4 h-4" /> SHAP remains explanatory-only</span>
        </div>
      </section>
    </div>
  );
}
