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

const friendlyRuleReasons: Record<string, string> = {
  URL_IP_HOST: "This address uses a number-based internet address instead of a recognizable website name. That can make the site owner harder to identify.",
  URL_USERINFO_TRICK: "The address contains a construction that can make text before the @ symbol look like the website name, while the real destination is after it.",
  URL_PUNYCODE: "The website name uses encoded characters. Scammers sometimes use look-alike letters to make a fake domain resemble a real one.",
  URL_HOMOGLYPH_SIGNAL: "Some letters in the website name may look similar to letters from another alphabet. That can be used to imitate a trusted website.",
  URL_EXCESSIVE_SUBDOMAINS: "There are many name segments before the main domain. This can make the real website owner harder to spot.",
  URL_SUSPICIOUS_TLD: "The domain ending is seen more often in suspicious links. This is only a warning sign, not proof by itself.",
  URL_SUSPICIOUS_PORT: "The link uses an unusual connection port rather than the standard web ports.",
  URL_NO_HTTPS: "The link does not use an encrypted HTTPS connection. This can expose information in transit, but does not by itself mean the site is a scam.",
  URL_OBFUSCATION: "Some characters in the address are encoded or disguised, making the destination harder to read.",
  URL_EXCESSIVE_LENGTH: "The address is unusually long. Long links can hide extra tracking or confusing destination details.",
  URL_SUSPICIOUS_KEYWORDS: "The address contains wording often used around sensitive account actions. Check the sender and destination before continuing.",
  URL_CREDENTIAL_KEYWORDS: "The address contains words associated with signing in or entering account details. Be careful if it asks for a password or one-time code.",
  URL_PAYMENT_KEYWORDS: "The address contains payment-related wording. Verify payment requests through the official app or website.",
  URL_URGENCY_KEYWORDS: "The address contains urgent-warning wording. Scammers often pressure people to act before checking.",
  URL_SHORTENER: "This is a shortened link, so the final destination is hidden until it is safely expanded.",
  URL_DOUBLE_SLASH_PATH: "The path contains an unusual double slash, which can sometimes be used to disguise where a link leads.",
  URL_BRAND_IMPERSONATION: "A recognizable brand name appears in a web address that is not its official domain. Check the actual domain carefully.",
};

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
       {status === "available" && typeof signalScore === "number"
       ? score(signalScore)
       : "—"}
    </div>
    </div>
  );
}

export default function ForensicsPage() {
  const [response, setResponse] = useState<ScanResponse | null>(null);

  useEffect(() => {
    queueMicrotask(() => setResponse(readSelectedScan()));
  }, []);

  const demoMetadata = response?.metadata;
  if (response && demoMetadata?.demo_mode === true) {
    const messageResult = isMessageScan(response);
    const demoInput = messageResult ? response.original_message : response.original_input;
    const demoVerdict = messageResult ? response.overall_verdict : response.verdict;
    const demoScore = messageResult ? response.overall_risk_score : response.risk_score;
    const demoCategory = String(demoMetadata.demo_category ?? demoVerdict).toUpperCase();
    return (
      <div className="max-w-5xl mx-auto space-y-6 pb-20">
        <header className="flex items-center justify-between border-b border-gray-200 pb-4">
          <div className="text-sm font-semibold uppercase tracking-widest text-gray-500">SEC OPS / <span className="text-gray-900">Demo Forensics</span></div>
          <Link href="/" className="text-sm font-bold text-gray-900 hover:text-blue-600">Back to scanner</Link>
        </header>
        <section className="rounded-2xl border border-indigo-200 bg-indigo-50 p-4">
          <p className="text-xs font-black uppercase tracking-widest text-indigo-900">Demo result — not a live model prediction</p>
          <p className="mt-1 text-sm leading-6 text-indigo-900">This result is a predefined presentation fixture. The live backend, ML classifier, risk fusion and SHAP were not run for this result.</p>
        </section>
        <section className="space-y-6 rounded-2xl border border-gray-200 bg-white p-8 shadow-sm">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h1 className="text-3xl font-bold text-gray-900">Threat Forensics Report</h1>
              <p className="mt-2 text-sm text-gray-500">{messageResult ? "Demonstration message scan" : "Demonstration URL scan"} · Fixture {String(demoMetadata.demo_fixture_id ?? "")}</p>
            </div>
            <span className={`rounded px-3 py-2 text-sm font-bold ${statusClass(formatVerdict(demoVerdict))}`}>{demoCategory}</span>
          </div>
          <div className="rounded-xl border border-gray-200 bg-gray-50 p-5">
            <p className="mb-2 text-xs font-bold uppercase tracking-wider text-gray-500">{messageResult ? "Demonstration message" : "Demonstration URL"}</p>
            <code className="break-all text-sm text-gray-900">{demoInput}</code>
          </div>
          <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-gray-200 bg-gray-50 p-6">
            <div>
              <p className="text-xs font-bold uppercase tracking-wider text-gray-500">Predefined demo risk score</p>
              <p className="mt-1 text-5xl font-black text-gray-900">{typeof demoScore === "number" ? demoScore.toFixed(1) : "—"}<span className="text-xl text-gray-400">/100</span></p>
            </div>
            <p className="max-w-md text-sm leading-6 text-gray-700">{response.recommendation}</p>
          </div>
          <div className="rounded-xl border border-gray-200 p-5">
            <h2 className="font-bold text-gray-900">What this demonstrates</h2>
            <ul className="mt-3 list-disc space-y-2 pl-5 text-sm leading-6 text-gray-700">
              <li>How ScamShield presents a category verdict and risk score.</li>
              <li>How URL and message scanning results can be displayed.</li>
              <li>How a user-facing recommendation is communicated.</li>
            </ul>
            <p className="mt-4 text-xs leading-5 text-gray-500">This fixture does not represent measured backend evidence, reputation checks, domain intelligence, redirect analysis or SHAP attribution. Switch Demo Mode off and run a live scan to see actual engine output.</p>
          </div>
          <div className="flex flex-wrap gap-3">
            <Link href="/" className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-700">Return to scanner</Link>
            <Link href="/history" className="rounded-lg border border-gray-300 px-4 py-2 text-sm font-semibold text-gray-700 hover:bg-gray-50">View scan history</Link>
          </div>
        </section>
      </div>
    );
  }

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
  const shapSignal = displayed.shap_result;
  const shapPayload = shapSignal && typeof shapSignal.value === "object" && shapSignal.value !== null
    ? shapSignal.value as Record<string, unknown>
    : null;
  const shapFeatures = Array.isArray(shapPayload?.top_features)
    ? shapPayload.top_features.filter((item): item is Record<string, unknown> => typeof item === "object" && item !== null)
    : [];

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

        <section className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="text-xs font-bold uppercase tracking-widest text-slate-500">Explainable AI · SHAP</p>
              <h2 className="mt-1 text-xl font-bold text-slate-950">Why did the ML model lean this way?</h2>
              <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
                SHAP measures how small text patterns in this URL moved the machine-learning model toward or away from its phishing-like class. It explains the ML model; it does not set the final risk score.
              </p>
            </div>
            <span className={`rounded-full px-3 py-1 text-xs font-semibold ${shapSignal?.status === "available" ? "bg-emerald-50 text-emerald-700" : "bg-amber-50 text-amber-800"}`}>
              SHAP: {String(shapSignal?.status ?? "not available")}
            </span>
          </div>
          {shapPayload ? (
            <>
              <p className="mt-5 rounded-lg bg-slate-50 p-4 text-sm leading-6 text-slate-800">
                {String(shapPayload.plain_language_summary ?? "The model returned feature-level explanations.")}
              </p>
              <div className="mt-4 grid gap-3 sm:grid-cols-3">
                <div className="rounded-lg border border-slate-200 p-3">
                  <p className="text-xs text-slate-500">Starting point (no URL text)</p>
                  <p className="mt-1 font-mono text-lg font-semibold">{typeof shapPayload.base_value === "number" ? shapPayload.base_value.toFixed(3) : "—"}</p>
                </div>
                <div className="rounded-lg border border-slate-200 p-3">
                  <p className="text-xs text-slate-500">Model output (log-odds)</p>
                  <p className="mt-1 font-mono text-lg font-semibold">{typeof shapPayload.prediction_value === "number" ? shapPayload.prediction_value.toFixed(3) : "—"}</p>
                </div>
                <div className="rounded-lg border border-slate-200 p-3">
                  <p className="text-xs text-slate-500">Highlighted fragments</p>
                  <p className="mt-1 font-mono text-lg font-semibold">{shapFeatures.length}</p>
                </div>
              </div>
              <p className="mt-3 text-xs leading-5 text-slate-500">
                The starting point is the model output before URL text features are added. Each row shows how one fragment moved the output from that starting point.
              </p>
              <div className="mt-5 space-y-3">
                {shapFeatures.map((feature, index) => {
                  const towardPhishing = feature.direction === "phishing";
                  return (
                    <article key={`${String(feature.feature)}-${index}`} className="rounded-xl border border-slate-200 p-4">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <code className="rounded bg-slate-100 px-2 py-1 text-sm font-semibold text-slate-900">{String(feature.feature)}</code>
                        <span className={`${towardPhishing ? "text-rose-700" : "text-emerald-700"} text-xs font-semibold`}>
                          {towardPhishing ? "↑ Nudged toward phishing" : "↓ Nudged toward benign"}
                        </span>
                      </div>
                      <p className="mt-2 text-sm leading-6 text-slate-700">{String(feature.plain_language ?? feature.explanation ?? "This text fragment influenced the model.")}</p>
                      <p className="mt-2 font-mono text-xs text-slate-500">SHAP contribution: {typeof feature.shap_value === "number" ? feature.shap_value.toFixed(5) : "—"} log-odds</p>
                    </article>
                  );
                })}
              </div>
              <details className="mt-5 rounded-lg border border-slate-200 p-4">
                <summary className="cursor-pointer text-sm font-semibold text-slate-700">Technical details</summary>
                <pre className="mt-3 overflow-auto rounded-lg bg-slate-950 p-4 text-xs text-slate-100">{JSON.stringify({ explainer_type: shapPayload.explainer_type, model_name: shapPayload.model_name, model_version: shapPayload.model_version, metadata: shapPayload.metadata }, null, 2)}</pre>
              </details>
            </>
          ) : (
            <p className="mt-4 rounded-lg bg-amber-50 p-4 text-sm leading-6 text-amber-900">
              {String(shapSignal?.error ?? "SHAP is not available for this scan. The rule-based and other available signals are still shown above.")}
            </p>
          )}
          <p className="mt-4 text-xs leading-5 text-slate-500">
            Important: character fragments are statistical clues, not standalone proof. SHAP values are in model log-odds space—not percentages or the final 0–100 ScamShield risk score. A low-risk result is not a guarantee of safety.
          </p>
        </section>

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
                  <p className="text-sm leading-6 text-gray-700 mt-2">{friendlyRuleReasons[String(item.rule_id ?? "")] ?? String(item.explanation ?? "A URL pattern matched a security rule.")}</p>
                  <details className="mt-2">
                    <summary className="cursor-pointer text-xs font-semibold text-gray-500">Technical reason</summary>
                    <p className="mt-2 text-xs leading-5 text-gray-500">{String(item.explanation ?? "No additional technical detail was returned.")}</p>
                    <p className="mt-1 font-mono text-[10px] text-gray-400">Feature: {String(item.feature ?? "—")} · Value: {String(item.value ?? "—")}</p>
                  </details>
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
