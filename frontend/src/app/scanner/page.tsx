"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Search, UploadCloud, Scan, Globe, LayoutGrid, FileText, User, Copy, Check } from "lucide-react";
import jsQR from "jsqr";
import { API_BASE_URL, saveScan, type ScanResponse } from "@/lib/scamshield";
import { clearPendingScan, readPendingScan, savePendingScan } from "@/lib/pending-scan";
import { supabase } from "@/lib/supabase";
import { buildDemoResponse, demoSamples } from "@/lib/demo-fixtures";

export default function ScannerPage() {
  const router = useRouter();
  const [inputMode, setInputMode] = useState<"url" | "message">("url");
  const [scanState, setScanState] = useState<"form" | "scanning" | "results">("form");
  const [inputValue, setInputValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const qrFileInputRef = useRef<HTMLInputElement>(null);
  const [demoMode, setDemoMode] = useState(false);
  const [selectedDemo, setSelectedDemo] = useState<{ id: string; mode: "url" | "message" } | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleDemoScan = (sampleId: string, mode: "url" | "message") => {
    const sample = demoSamples.find((item) => item.id === sampleId);
    if (!sample) {
      setError("The selected demonstration example could not be found.");
      return;
    }
    setError(null);
    setScanState("results");
    saveScan(buildDemoResponse(sample, mode));
    router.push("/forensics");
  };

  const copyDemoText = async (value: string, key: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedId(key);
      window.setTimeout(() => setCopiedId((current) => current === key ? null : current), 1600);
    } catch {
      setError("Clipboard access was blocked by the browser. Select and copy the text manually.");
    }
  };

  const handleScan = useCallback(async (value = inputValue, mode = inputMode) => {
    if (!value.trim()) return;
    setScanState("scanning");
    setError(null);
    try {
      const session = supabase ? (await supabase.auth.getSession()).data.session : null;
      const requestId = crypto.randomUUID();
      const response = await fetch(`${API_BASE_URL}/scan`, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          ...(session?.access_token ? { Authorization: `Bearer ${session.access_token}` } : {}),
        },
        body: JSON.stringify({
          input: value,
          input_type: mode,
          request_id: requestId,
        }),
      });
      const body = (await response.json()) as ScanResponse | { error?: string };
      if (!response.ok) {
        if (response.status === 401) {
          savePendingScan({ request_id: requestId, input: value, input_type: mode, return_to: "/forensics" });
          router.push("/auth/login");
          return;
        }
        throw new Error("error" in body ? body.error ?? "Scan failed" : "Scan failed");
      }
      saveScan(body as ScanResponse);
      setScanState("results");
      router.push("/forensics");
    } catch (scanError) {
      setScanState("form");
      setError(scanError instanceof Error ? scanError.message : "Unable to reach ScamShield API");
    }
  }, [inputMode, inputValue, router]);

  useEffect(() => {
    const pending = readPendingScan();
    if (!pending || !supabase) return;
    void supabase.auth.getSession().then(({ data }) => {
      if (!data.session) return;
      void handleScan(pending.input, pending.input_type).then(() => clearPendingScan());
    });
  }, [handleScan]);

  const handleQrFile = async (file: File | undefined) => {
    if (!file) return;
    setError(null);

    try {
      const image = await createImageBitmap(file);
      const canvas = document.createElement("canvas");
      canvas.width = image.width;
      canvas.height = image.height;
      const context = canvas.getContext("2d");
      if (!context) throw new Error("Unable to read QR image");
      context.drawImage(image, 0, 0);
      image.close();

      const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
      const decoded = jsQR(imageData.data, imageData.width, imageData.height);
      if (!decoded?.data.trim()) {
        throw new Error("No QR code detected");
      }

      setInputMode("url");
      setInputValue(decoded.data);
      await handleScan(decoded.data, "url");
    } catch (scanError) {
      setScanState("form");
      setError(scanError instanceof Error ? scanError.message : "Unable to decode QR image");
    }
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6 pb-12 pt-2">
      {/* Top Header */}
      <header className="flex items-center justify-between border-b border-gray-200 pb-4">
        <div className="text-sm font-semibold text-gray-500 uppercase tracking-widest flex gap-1">
          SEC OPS / <span className="text-gray-900 font-bold">Overview</span>
        </div>
        <div className="flex items-center gap-4 text-sm font-semibold text-gray-600">
          <div className="flex items-center gap-2 px-3 py-1.5 bg-gray-100/80 rounded-full border border-gray-200">
            <span className="w-2 h-2 rounded-full bg-green-500 shadow-[0_0_4px_rgba(34,197,94,0.4)]"></span>
            <span className="text-[11px] uppercase tracking-wider font-bold">Operational</span>
          </div>
          <a href="#" className="hover:text-gray-900 transition-colors">Documentation</a>
          <span className="px-2 py-1 bg-gray-200 text-gray-600 rounded text-xs font-mono font-bold">v2.4.1</span>
          <div className="w-8 h-8 bg-[#0F172A] rounded-full flex items-center justify-center text-white shadow-sm cursor-pointer">
            <User className="w-4 h-4" />
          </div>
        </div>
      </header>

      {/* Preview Banner */}
      <div className="bg-gray-100 rounded-xl p-2.5 flex items-center justify-between border border-gray-200/60 shadow-sm">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 font-mono font-bold text-gray-500 text-xs tracking-wider uppercase ml-2">
            <LayoutGrid className="w-4 h-4" />
            Preview State:
          </div>
          <div className="flex items-center gap-1 text-gray-500 font-semibold text-sm">
            <span className={`px-4 py-1.5 rounded-lg transition-colors cursor-pointer ${scanState === 'form' ? 'bg-white text-gray-900 font-bold shadow-sm border border-gray-200/50' : 'hover:bg-gray-200'}`} onClick={() => setScanState('form')}>Scanner Form</span>
            <span className={`px-4 py-1.5 rounded-lg transition-colors cursor-pointer ${scanState === 'scanning' ? 'bg-white text-gray-900 font-bold shadow-sm border border-gray-200/50' : 'hover:bg-gray-200'}`} onClick={() => setScanState('scanning')}>Scanning...</span>
            <span className={`px-4 py-1.5 rounded-lg transition-colors cursor-pointer ${scanState === 'results' ? 'bg-white text-gray-900 font-bold shadow-sm border border-gray-200/50' : 'hover:bg-gray-200'}`} onClick={() => setScanState('results')}>Results Matrix</span>
          </div>
        </div>
        <div className="flex items-center gap-2 font-mono text-[10px] font-bold uppercase tracking-wider">
          <span className="text-gray-500 mr-1">VERDICT:</span>
          <span className="text-red-700 bg-red-100/80 border border-red-200 px-2.5 py-1 rounded">91 DANGEROUS</span>
          <span className="text-blue-700 bg-blue-100/80 border border-blue-200 px-2.5 py-1 rounded">58 SUSPICIOUS</span>
          <span className="text-gray-700 bg-white border border-gray-200 px-2.5 py-1 rounded">06 SAFE</span>
          <span className="bg-[#0F172A] text-white px-2.5 py-1 rounded shadow-sm border border-gray-900 ml-1">SMS BATCH (3 URLs)</span>
        </div>
      </div>

      {/* Title section */}
      <div className="py-2">
        <p className="text-[10px] font-mono text-gray-500 mb-2 uppercase tracking-widest font-bold">
          THREAT TELEMETRY & DOMAIN REPUTATION • SEC-ENG 2025-Q2
        </p>
        <h2 className="text-[2.5rem] leading-none font-extrabold tracking-tight mb-4 text-gray-900">
          Enterprise Scam & Threat Inspector
        </h2>
        <p className="text-gray-600 max-w-4xl text-lg leading-relaxed font-medium">
          Deconstruct suspicious URLs, emails, SMS text payloads, and QR vectors using multi-layered heuristic analysis, brand impersonation detection, and synthetic sandbox queries.
        </p>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-12 gap-6 items-start">
        
        {/* Left Col (Form) */}
        <div className="col-span-8">
          <div className="bg-white rounded-2xl border border-gray-200 shadow-sm relative overflow-hidden">
            {scanState === 'scanning' && (
               <div className="absolute inset-0 bg-white/90 backdrop-blur-sm z-10 flex flex-col items-center justify-center">
                  <div className="w-10 h-10 border-4 border-gray-200 border-t-[#0F172A] rounded-full animate-spin mb-4"></div>
                  <h3 className="text-lg font-bold text-gray-900">Analyzing Payload...</h3>
                  <p className="text-xs text-gray-500 font-mono mt-2 font-bold uppercase tracking-wider">Resolving canonical redirects & SSL chains</p>
               </div>
            )}
            
            <div className="p-8 pb-6">
              <div className="flex items-center justify-between mb-6">
                <div className="flex gap-2 bg-gray-50 p-1.5 rounded-lg border border-gray-200">
                  <button 
                    onClick={() => setInputMode("url")}
                    className={`px-4 py-2 rounded-md text-xs uppercase tracking-wider font-bold flex items-center gap-2 transition-all ${
                      inputMode === "url" ? "bg-white text-gray-900 shadow-sm border border-gray-200/50" : "text-gray-500 hover:text-gray-700"
                    }`}
                  >
                    <Globe className="w-4 h-4" />
                    URL / Domain
                  </button>
                  <button 
                    onClick={() => setInputMode("message")}
                    className={`px-4 py-2 rounded-md text-xs uppercase tracking-wider font-bold flex items-center gap-2 transition-all ${
                      inputMode === "message" ? "bg-white text-gray-900 shadow-sm border border-gray-200/50" : "text-gray-500 hover:text-gray-700"
                    }`}
                  >
                    <FileText className="w-4 h-4" />
                    Raw Message / SMS
                  </button>
                </div>
                <span className="text-[10px] font-mono font-bold text-gray-400 bg-gray-50 px-2 py-1 rounded border border-gray-200">RFC 3986 COMPLIANT</span>
              </div>

              <div className="space-y-3">
                <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest block">
                  TARGET WEB IDENTIFIER
                </label>
                
                {inputMode === "url" ? (
                  <div className="flex gap-3 h-14">
                    <div className="flex-1 flex items-center bg-gray-50/50 border border-gray-300 rounded-lg px-4 focus-within:border-gray-500 focus-within:ring-2 focus-within:ring-gray-100 transition-all shadow-inner">
                      <div className="text-gray-400 mr-3">
                        <Globe className="w-5 h-5" />
                      </div>
                      <input 
                        type="text" 
                        value={inputValue}
                        onChange={(e) => { setInputValue(e.target.value); setSelectedDemo(null); }}
                        placeholder="https://secure-login-chase-update.com/account/verify"
                        className="bg-transparent border-none outline-none w-full text-gray-900 font-mono text-sm placeholder:text-gray-400 font-medium"
                      />
                    </div>
                    <button 
                      onClick={() => demoMode && selectedDemo ? handleDemoScan(selectedDemo.id, selectedDemo.mode) : void handleScan()}
                      disabled={!inputValue.trim()}
                      className="bg-[#0F172A] text-white px-8 h-full rounded-lg font-bold flex items-center gap-2 hover:bg-gray-800 transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
                    >
                      <Scan className="w-5 h-5" />
                      Deep Scan
                    </button>
                  </div>
                ) : (
                  <div className="flex flex-col gap-3">
                    <textarea 
                      rows={5}
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      placeholder="Paste full SMS or email body here..."
                      className="w-full bg-gray-50/50 border border-gray-300 rounded-lg p-4 font-mono text-sm text-gray-900 focus:outline-none focus:border-gray-500 focus:ring-2 focus:ring-gray-100 transition-all shadow-inner resize-none placeholder:text-gray-400 font-medium"
                    ></textarea>
                    <button 
                      onClick={() => void handleScan()}
                      disabled={!inputValue.trim()}
                      className="bg-[#0F172A] text-white h-14 rounded-lg font-bold flex items-center justify-center gap-2 hover:bg-gray-800 transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-sm w-full"
                    >
                      <Scan className="w-5 h-5" />
                      Extract & Deep Scan
                    </button>
                  </div>
                )}
                
                <p className="text-sm text-gray-500 font-medium mt-3">
                  Scans use the frozen ScamShield backend. External intelligence remains explicitly unavailable when it is not configured.
                </p>
                {error && (
                  <p role="alert" className="text-sm text-red-700 bg-red-50 border border-red-200 rounded-lg p-3">
                    {error}
                  </p>
                )}
              </div>
            </div>

            <div className="bg-gray-50/80 border-t border-gray-200 p-6 pb-8">
              <div className="flex flex-wrap items-center justify-between gap-3 mb-5">
                <div>
                  <p className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">DEMO TEST LIBRARY</p>
                  <p className="mt-1 text-xs text-gray-500">30 URL fixtures and 30 message fixtures, grouped by expected demonstration category.</p>
                </div>
                <button
                  type="button"
                  aria-pressed={demoMode}
                  onClick={() => { setDemoMode((value) => !value); setSelectedDemo(null); }}
                  className={`rounded-lg border px-3 py-2 text-xs font-bold transition-colors ${demoMode ? "border-indigo-300 bg-indigo-50 text-indigo-800" : "border-gray-300 bg-white text-gray-700 hover:bg-gray-100"}`}
                >
                  Demo Mode: {demoMode ? "ON" : "OFF"}
                </button>
              </div>
              {demoMode && (
                <div className="mb-5 rounded-lg border border-indigo-200 bg-indigo-50 p-3 text-xs leading-5 text-indigo-900">
                  <strong>DEMO MODE ACTIVE.</strong> Use a fixture's Show URL result or Show message result button for a deterministic, predefined presentation result. Manually entered text continues through the live backend.
                </div>
              )}
              <div className="space-y-6">
                {(["SAFE", "SUSPICIOUS", "DANGEROUS"] as const).map((category) => {
                  const categorySamples = demoSamples.filter((sample) => sample.category === category);
                  const tone = category === "SAFE"
                    ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                    : category === "SUSPICIOUS"
                      ? "border-amber-200 bg-amber-50 text-amber-800"
                      : "border-rose-200 bg-rose-50 text-rose-800";
                  return (
                    <section key={category} className="rounded-xl border border-gray-200 bg-white p-4">
                      <div className="mb-3 flex items-center justify-between gap-2">
                        <span className={`rounded-full border px-3 py-1 text-[10px] font-bold tracking-wider ${tone}`}>{category}</span>
                        <span className="text-[10px] font-mono text-gray-500">10 URLS · 10 MESSAGES</span>
                      </div>
                      <div className="space-y-3">
                        {categorySamples.map((sample, index) => {
                          const urlCopyKey = `${sample.id}-url`;
                          const messageCopyKey = `${sample.id}-message`;
                          return (
                            <article key={sample.id} className="rounded-lg border border-gray-200 p-3">
                              <div className="mb-2 flex items-center justify-between gap-2">
                                <p className="text-xs font-semibold text-gray-900">{index + 1}. {sample.title}</p>
                                <span className="text-[10px] text-gray-400">FIXTURE</span>
                              </div>
                              <div className="space-y-2">
                                <div className="flex items-start gap-2">
                                  <div className="min-w-0 flex-1">
                                    <p className="mb-1 text-[10px] font-bold uppercase tracking-wider text-gray-500">URL</p>
                                    <code className="block break-all rounded bg-gray-50 p-2 text-[11px] text-gray-700">{sample.url}</code>
                                  </div>
                                  <button type="button" onClick={() => void copyDemoText(sample.url, urlCopyKey)} aria-label="Copy URL" title="Copy URL" className="mt-5 rounded-md border border-gray-200 p-2 text-gray-600 hover:bg-gray-100">
                                    {copiedId === urlCopyKey ? <Check className="h-4 w-4 text-emerald-600" /> : <Copy className="h-4 w-4" />}
                                  </button>
                                </div>
                                <div className="flex items-start gap-2">
                                  <div className="min-w-0 flex-1">
                                    <p className="mb-1 text-[10px] font-bold uppercase tracking-wider text-gray-500">MESSAGE / SMS</p>
                                    <p className="rounded bg-gray-50 p-2 text-[11px] leading-5 text-gray-700">{sample.message}</p>
                                  </div>
                                  <button type="button" onClick={() => void copyDemoText(sample.message, messageCopyKey)} aria-label="Copy message" title="Copy message" className="mt-5 rounded-md border border-gray-200 p-2 text-gray-600 hover:bg-gray-100">
                                    {copiedId === messageCopyKey ? <Check className="h-4 w-4 text-emerald-600" /> : <Copy className="h-4 w-4" />}
                                  </button>
                                </div>
                              </div>
                              <div className="mt-3 flex flex-wrap gap-2">
                                <button type="button" onClick={() => { setInputMode("url"); setInputValue(sample.url); setSelectedDemo({ id: sample.id, mode: "url" }); }} className="rounded-md border border-gray-300 px-3 py-2 text-[11px] font-semibold text-gray-700 hover:bg-gray-50">Load URL</button>
                                <button type="button" onClick={() => { setInputMode("message"); setInputValue(sample.message); setSelectedDemo({ id: sample.id, mode: "message" }); }} className="rounded-md border border-gray-300 px-3 py-2 text-[11px] font-semibold text-gray-700 hover:bg-gray-50">Load message</button>
                                {demoMode && (
                                  <>
                                    <button type="button" onClick={() => { setInputMode("url"); setInputValue(sample.url); setSelectedDemo({ id: sample.id, mode: "url" }); handleDemoScan(sample.id, "url"); }} className="rounded-md bg-slate-900 px-3 py-2 text-[11px] font-semibold text-white hover:bg-slate-700">Show URL result</button>
                                    <button type="button" onClick={() => { setInputMode("message"); setInputValue(sample.message); setSelectedDemo({ id: sample.id, mode: "message" }); handleDemoScan(sample.id, "message"); }} className="rounded-md bg-indigo-700 px-3 py-2 text-[11px] font-semibold text-white hover:bg-indigo-600">Show message result</button>
                                  </>
                                )}
                              </div>
                            </article>
                          );
                        })}
                      </div>
                    </section>
                  );
                })}
              </div>
              <p className="mt-4 text-[10px] leading-4 text-gray-500">
                Demo verdicts and scores are predefined presentation fixtures, not predictions from the live detection engine. Suspicious and dangerous examples use reserved .example and .invalid domains and are not real malicious destinations. QR image upload remains available separately.
              </p>
            </div>
          </div>
        </div>

        {/* Right Col */}
        <div className="col-span-4 space-y-6">
          {/* QR Upload */}
          <div className="bg-white rounded-2xl p-6 border border-gray-200 shadow-sm h-[320px] flex flex-col">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-[1.1rem] font-bold text-gray-900 flex items-center gap-2">
                <Scan className="w-5 h-5 text-gray-700" />
                QR & Image Intake
              </h3>
              <span className="text-[10px] font-mono font-bold text-gray-500 uppercase tracking-widest bg-gray-50 border border-gray-200 px-2 py-1 rounded">OCR/QR</span>
            </div>
            <p className="text-[13px] text-gray-600 mb-6 font-medium leading-relaxed">
              Upload screenshot of suspicious WhatsApp, iMessage, or physical postal scam QR token.
            </p>
            <input
              ref={qrFileInputRef}
              type="file"
              accept="image/png,image/jpeg,image/webp"
              className="sr-only"
              tabIndex={-1}
              onChange={(event) => {
                void handleQrFile(event.target.files?.[0]);
                event.target.value = "";
              }}
            />
            <button
              type="button"
              onClick={() => qrFileInputRef.current?.click()}
              className="border-2 border-dashed border-gray-300 rounded-xl bg-gray-50/50 flex-1 flex flex-col items-center justify-center text-center cursor-pointer hover:bg-gray-100 hover:border-gray-400 transition-all group w-full"
            >
              <UploadCloud className="w-6 h-6 text-gray-400 mb-3 group-hover:text-gray-600 transition-colors" />
              <p className="text-sm font-bold text-gray-700">Drop image or browse</p>
              <p className="text-[10px] font-mono text-gray-400 mt-2 font-bold tracking-widest uppercase">PNG, JPG, HEIC up to 10MB</p>
            </button>
          </div>

          {/* Engine Telemetry */}
          <div className="bg-white rounded-2xl p-6 border border-gray-200 shadow-sm">
            <h3 className="font-bold text-gray-900 mb-5">Engine Telemetry</h3>
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-gray-50 rounded-lg p-3.5 border border-gray-200 shadow-sm">
                <p className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-1.5">Feed Latency</p>
                <p className="font-mono text-[15px] font-bold text-gray-900">14ms</p>
              </div>
              <div className="bg-gray-50 rounded-lg p-3.5 border border-gray-200 shadow-sm">
                <p className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-1.5">Feed Signatures</p>
                <p className="font-mono text-[15px] font-bold text-gray-900">4.82M</p>
              </div>
              <div className="bg-gray-50 rounded-lg p-3.5 border border-gray-200 shadow-sm">
                <p className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-1.5">Cert Checker</p>
                <p className="font-mono text-[15px] font-bold text-gray-900">CRL/OCSP v3</p>
              </div>
              <div className="bg-gray-50 rounded-lg p-3.5 border border-gray-200 shadow-sm">
                <p className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-1.5">Sandbox Proxy</p>
                <p className="font-mono text-[15px] font-bold text-gray-900 leading-tight">US-EAST <span className="text-gray-400 block text-[10px] mt-0.5 font-sans tracking-wide uppercase">(Isolated)</span></p>
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
