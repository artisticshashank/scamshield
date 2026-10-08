"use client";

import { useState, type Dispatch, type SetStateAction } from "react";
import { Copy, RefreshCw, Terminal, CheckCircle2, AlertTriangle, Key } from "lucide-react";

export default function ApiDocsPage() {
  const [activeLang, setActiveLang] = useState<"cURL" | "Node.js" | "Python">("cURL");
  const [copied, setCopied] = useState(false);
  const [keyCopied, setKeyCopied] = useState(false);
  const [sandboxRes, setSandboxRes] = useState<string | null>(null);

  const copyToClipboard = (
    text: string,
    setter: Dispatch<SetStateAction<boolean>>,
  ) => {
    navigator.clipboard.writeText(text);
    setter(true);
    setTimeout(() => setter(false), 2000);
  };

  const codeSnippets = {
    cURL: `curl -X POST https://api.scamshield.net/v1/scan \\
  -H "Authorization: Bearer scam_live_94Bf..." \\
  -H "Content-Type: application/json" \\
  -d '{
    "url": "https://example.com/verify",
    "deep_crawl": false
  }'`,
    "Node.js": `const fetch = require('node-fetch');

fetch('https://api.scamshield.net/v1/scan', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer scam_live_94Bf...',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    url: "https://example.com/verify",
    deep_crawl: false
  })
}).then(res => res.json());`,
    Python: `import requests

url = "https://api.scamshield.net/v1/scan"
headers = {
    "Authorization": "Bearer scam_live_94Bf...",
    "Content-Type": "application/json"
}
data = {
    "url": "https://example.com/verify",
    "deep_crawl": False
}

response = requests.post(url, json=data, headers=headers)`
  };

  return (
    <div className="max-w-6xl mx-auto space-y-8 pb-12">
      <header className="flex items-center justify-between border-b border-gray-200 pb-4">
        <div className="text-sm font-semibold text-gray-500 uppercase tracking-widest">
          Sec Ops / <span className="text-gray-900">API Documentation</span>
        </div>
      </header>

      <div className="space-y-4">
        <div className="flex gap-2 text-[10px] font-mono font-bold uppercase tracking-widest">
          <span className="bg-blue-100 border border-blue-200 text-blue-800 px-2 py-1 rounded">v1.4 REST API</span>
          <span className="bg-gray-100 border border-gray-200 text-gray-700 px-2 py-1 rounded">99.98% SLA</span>
          <span className="bg-gray-100 border border-gray-200 text-gray-700 px-2 py-1 rounded">100 REQ / MIN</span>
        </div>
        <h2 className="text-4xl font-extrabold tracking-tight text-gray-900">
          Scan URLs programmatically
        </h2>
        <div className="flex items-start justify-between">
          <p className="text-gray-600 max-w-2xl text-lg font-medium leading-relaxed">
            Integrate ScamShield&apos;s multi-layered URL and message threat analysis into your applications, security bots, and email gateways.
          </p>
          <div className="text-right text-[10px] font-mono text-gray-500 uppercase tracking-widest bg-white border border-gray-200 p-3 rounded-lg shadow-sm">
            <div>Target Host</div>
            <div className="font-bold text-gray-900 mb-2">api.scamshield.net/v1</div>
            <div>Auth Scheme</div>
            <div className="font-bold text-gray-900">Bearer Token</div>
          </div>
        </div>
      </div>

      <div className="bg-white border border-gray-200 rounded-xl p-5 shadow-sm flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="w-10 h-10 rounded-full bg-gray-100 border border-gray-200 flex items-center justify-center">
            <Key className="w-5 h-5 text-gray-700" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-bold text-gray-900">Live API Credentials</h3>
              <span className="bg-green-100 border border-green-200 text-green-800 text-[10px] font-bold px-2 py-0.5 rounded uppercase tracking-widest">Production</span>
            </div>
            <p className="text-xs text-gray-500 mt-1 font-medium">Include this key in the <code className="bg-gray-100 border border-gray-200 text-gray-800 px-1 py-0.5 rounded font-mono font-bold">Authorization: Bearer &lt;TOKEN&gt;</code> header for all scan requests.</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <div className="bg-gray-50 border border-gray-200 rounded-lg px-4 py-2 font-mono text-sm font-bold text-gray-900 flex items-center gap-4 shadow-inner">
            <span className="text-gray-400 text-[10px] tracking-widest uppercase">Secret</span> scam_live_94Bf••••••••••••••4a91
            <button onClick={() => copyToClipboard('scam_live_94Bf12345678904a91', setKeyCopied)} className="text-gray-400 hover:text-gray-900 transition-colors">
               {keyCopied ? <CheckCircle2 className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
            </button>
          </div>
          <button className="bg-gray-900 text-white px-4 py-2 rounded-lg font-bold text-sm flex items-center gap-2 hover:bg-gray-800 shadow-sm transition-colors">
            <RefreshCw className="w-4 h-4" /> Generate new key
          </button>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-8 items-start">
        <div className="col-span-2 space-y-8">
          <div className="flex items-center justify-between border-b border-gray-200 pb-2">
            <h3 className="text-xl font-extrabold flex items-center gap-2 text-gray-900">
              <Terminal className="w-5 h-5 text-gray-600" /> Endpoints Reference
            </h3>
            <span className="text-[10px] font-mono font-bold text-gray-500 uppercase tracking-widest">4 Core Operations</span>
          </div>

          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className="bg-gray-900 text-white px-2 py-1 rounded text-xs font-bold font-mono">POST</span>
                <code className="text-lg font-bold text-gray-900 font-mono">/scan</code>
              </div>
              <span className="text-[10px] text-gray-500 font-bold uppercase tracking-widest bg-gray-100 border border-gray-200 px-2 py-1 rounded">Single URL Inspection</span>
            </div>
            <p className="text-gray-600 text-sm font-medium leading-relaxed">
              Dispatches synchronous machine learning heuristic parsing, DNS registry validation, WHOIS age calculation, and SSL certificate verification against known blacklists.
            </p>
            
            <div className="bg-gray-900 rounded-xl overflow-hidden shadow-lg border border-gray-800">
              <div className="flex items-center justify-between px-4 py-2 border-b border-gray-800 text-xs font-mono font-bold text-gray-400 bg-gray-950">
                <div className="flex gap-4">
                  {(['cURL', 'Node.js', 'Python'] as const).map(lang => (
                    <button 
                      key={lang} 
                      onClick={() => setActiveLang(lang)}
                      className={`pb-2 -mb-2 transition-colors ${activeLang === lang ? 'text-white border-b-2 border-white' : 'hover:text-gray-300'}`}
                    >
                      {lang}
                    </button>
                  ))}
                </div>
                <button 
                  onClick={() => copyToClipboard(codeSnippets[activeLang], setCopied)} 
                  className="flex items-center gap-1 hover:text-white transition-colors"
                >
                  {copied ? <><CheckCircle2 className="w-3 h-3 text-green-400" /> Copied!</> : <><Copy className="w-3 h-3" /> Copy</>}
                </button>
              </div>
              <pre className="p-4 text-sm text-green-400 font-mono overflow-x-auto whitespace-pre">
                {codeSnippets[activeLang]}
              </pre>
            </div>

            <div className="bg-white rounded-xl border border-gray-200 overflow-hidden text-sm font-mono shadow-sm">
              <div className="flex items-center justify-between px-4 py-2 border-b border-gray-200 text-[10px] font-bold text-gray-500 uppercase tracking-widest bg-gray-50">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-green-500 shadow-[0_0_4px_rgba(34,197,94,0.8)]"></span> 200 OK — JSON RESPONSE PREVIEW
                </div>
                <span className="text-gray-400">~62ms</span>
              </div>
              <pre className="p-4 text-gray-800 font-bold">
{`{
  "status": "completed",
  "risk_score": 91,
  "verdict": "dangerous",
  "reasons": [
    "lookalike domain",
    "suspicious redirect",
    "recent registration"
  ],
  "scan_id": "scn_99tt3abx2"
}`}
              </pre>
            </div>
          </div>
        </div>

        <div className="col-span-1">
          <div className="bg-white rounded-xl border border-gray-200 shadow-sm sticky top-6">
            <div className="p-4 border-b border-gray-200 bg-gray-50 rounded-t-xl">
              <h3 className="font-extrabold text-gray-900 flex items-center gap-2">API Sandbox Playground</h3>
              <p className="text-xs text-gray-500 mt-1 font-medium leading-relaxed">Trigger live simulated requests without consuming your operational workspace quota.</p>
            </div>
            
            <div className="p-5 space-y-4">
              <div>
                <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest block mb-2">Endpoint</label>
                <div className="flex gap-2">
                  <span className="bg-gray-900 text-white px-3 py-2 rounded text-xs font-bold font-mono">POST</span>
                  <span className="bg-gray-50 text-gray-900 px-3 py-2 rounded text-sm font-mono font-bold border border-gray-200 flex-1 shadow-inner">/v1/scan</span>
                </div>
              </div>
              
              <div>
                <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest block mb-2">Target URL to inspect <span className="float-right text-gray-400">String (FQDN)</span></label>
                <input type="text" value="https://secure-login.paypal-update.com/veri" className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm font-mono font-bold text-gray-900 focus:outline-none focus:border-blue-500 shadow-inner bg-gray-50" readOnly />
              </div>

              <div className="flex items-center justify-between border border-gray-200 rounded-lg p-3 bg-white shadow-sm">
                <div>
                  <div className="text-sm font-bold text-gray-900">Deep Crawl & Sandbox</div>
                  <div className="text-[10px] font-mono text-gray-500 font-bold mt-0.5 tracking-wider">Renders headless browser snapshot</div>
                </div>
                <div className="w-10 h-6 bg-gray-900 rounded-full relative shadow-inner cursor-pointer">
                  <div className="w-4 h-4 bg-white rounded-full absolute right-1 top-1 shadow-sm"></div>
                </div>
              </div>

              <button 
                onClick={() => {
                  setSandboxRes('// Connecting to sandbox...\n// Running heuristic parsers...\n// Fetching WHOIS data...\n{\n  "status": "completed",\n  "risk_score": 91,\n  "verdict": "dangerous"\n}')
                }}
                className="w-full bg-gray-900 text-white font-bold text-sm py-3 rounded-lg flex items-center justify-center gap-2 hover:bg-gray-800 transition-colors shadow-sm"
              >
                ▶ Execute Scan Payload
              </button>

              <div className="mt-6">
                <div className="flex items-center justify-between text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-2">
                  <span>Response Terminal</span>
                  <span className={sandboxRes ? "text-green-500" : "text-gray-400"}>{sandboxRes ? "SUCCESS" : "IDLE"}</span>
                </div>
                <div className="bg-gray-950 rounded-lg h-36 p-3 font-mono text-xs text-gray-400 border border-gray-800 shadow-inner overflow-auto whitespace-pre">
                  {sandboxRes || "// Ready. Press 'Execute Scan Payload' to trigger request..."}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
