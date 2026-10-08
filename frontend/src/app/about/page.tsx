import { Network, ShieldCheck, Lock, Activity, RefreshCcw, EyeOff, ServerCrash, Zap, AlertTriangle, Clock } from "lucide-react";

export default function AboutPage() {
  return (
    <div className="max-w-5xl mx-auto space-y-8 pb-12">
      {/* Top Header */}
      <header className="flex items-center justify-between border-b border-gray-200 pb-4">
        <div className="text-sm font-semibold text-gray-500 uppercase tracking-widest">
          Sec Ops / <span className="text-gray-900">Overview</span>
        </div>
      </header>

      {/* Main Content */}
      <div className="space-y-10">
        <div>
          <div className="flex items-center justify-between">
             <p className="text-xs font-mono text-gray-500 mb-2 uppercase tracking-wider">
               DETECTION ARCHITECTURE & METHODOLOGY
             </p>
             <span className="bg-gray-100 border border-gray-200 text-gray-600 text-xs font-mono font-bold px-3 py-1 rounded-full flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-blue-500"></span> PIPELINE LATENCY SLA: &lt;140MS
             </span>
          </div>
          <h2 className="text-4xl font-bold tracking-tight text-gray-900 mb-4">
            How ScamShield works
          </h2>
          <p className="text-gray-600 max-w-3xl text-lg leading-relaxed">
            A multi-layered threat evaluation pipeline designed to explain phishing verdicts with clear evidence, not opaque black-box scores.
          </p>
        </div>

        {/* Visual Pipeline */}
        <div className="bg-white border border-gray-200 rounded-2xl p-6 shadow-sm">
           <div className="flex items-center justify-between mb-6">
              <h3 className="font-bold text-gray-900 flex items-center gap-2"><Network className="w-5 h-5 text-blue-600" /> Visual Threat Analysis Pipeline</h3>
              <div className="text-xs font-mono text-gray-500 bg-gray-50 border border-gray-200 px-3 py-1 rounded">7 Stages Active <span className="text-gray-300 mx-2">|</span> Avg: 58.4ms</div>
           </div>

           <div className="flex items-center gap-2 mb-8 overflow-x-auto pb-4">
              {/* Nodes */}
              {[
                { step: 'ST-01', ms: '~1.2ms', title: 'Ingested URL / Message', active: true },
                { step: 'ST-02', ms: '~3.8ms', title: 'De-obfuscation Normalization', active: false },
                { step: 'ST-03', ms: '~6.4ms', title: 'Heuristic Security Rules', active: false },
                { step: 'ST-04', ms: '~18.2ms', title: 'Machine Learning Models', active: false },
                { step: 'ST-05', ms: '~14.1ms', title: 'Threat Reputation Intel', active: false },
                { step: 'ST-06', ms: '~11.5ms', title: 'Domain & DNS Telemetry', active: false },
                { step: 'ST-07', ms: '~3.2ms', title: 'Risk Scoring & Explanation', active: false }
              ].map((node, i) => (
                <div key={i} className="flex items-center">
                   <div className={`flex flex-col items-center justify-center p-4 rounded-xl border-2 w-32 h-32 text-center transition-all ${
                     node.active ? 'bg-gray-900 border-gray-900 text-white shadow-lg scale-105' : 'bg-white border-gray-200 text-gray-600 hover:border-gray-300'
                   }`}>
                      <div className={`text-[10px] font-mono mb-2 ${node.active ? 'text-gray-400' : 'text-gray-400'}`}>{node.step} <span className="ml-1 opacity-75">{node.ms}</span></div>
                      <div className={`text-xs font-bold leading-tight ${node.active ? 'text-white' : 'text-gray-900'}`}>{node.title}</div>
                   </div>
                   {i < 6 && <div className="w-6 border-t-2 border-dashed border-gray-300 mx-1"></div>}
                </div>
              ))}
           </div>

           {/* Stage Details */}
           <div className="bg-gray-50 border border-gray-200 rounded-xl p-5">
              <div className="flex items-center justify-between mb-4 border-b border-gray-200 pb-3">
                 <h4 className="font-bold text-gray-900 text-sm flex items-center gap-2"><span className="bg-gray-900 text-white px-2 py-0.5 rounded text-[10px]">STAGE 1 / 7</span> Ingested URL / Message Preprocessing</h4>
                 <div className="text-[10px] font-mono text-gray-500 uppercase flex items-center gap-4">
                    <span>Engine Step: ~1.2ms latency</span>
                    <span className="flex items-center gap-1 text-blue-600"><Lock className="w-3 h-3" /> Zero Execution Sandbox</span>
                 </div>
              </div>
              <div className="grid grid-cols-3 gap-6">
                 <div>
                    <h5 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-2">Algorithms & Parsers</h5>
                    <p className="text-xs text-gray-600">RFC 3986 Lexer, MIME stream reader, Base64 & Unicode sanitizer</p>
                 </div>
                 <div>
                    <h5 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-2">Target Threat Signals</h5>
                    <p className="text-xs text-gray-600">Zero width characters, hidden protocol schemes, nested URI encodings, payload size anomalies</p>
                 </div>
                 <div>
                    <h5 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-2">Security Guarantee</h5>
                    <p className="text-xs text-gray-600">Strict static parse tree only. Zero headless browser instantiation; payloads never touch V8 runtime.</p>
                 </div>
              </div>
              <div className="mt-4 pt-4 border-t border-gray-200 flex items-center gap-4">
                 <div className="text-[10px] font-bold text-gray-500 uppercase tracking-wider flex items-center gap-1"><Activity className="w-3 h-3" /> Telemetry Sample Output</div>
                 <code className="flex-1 bg-white border border-gray-200 rounded px-3 py-2 text-xs font-mono text-gray-600 shadow-sm truncate">
                   {`{"raw_scheme":"https", "tokens_extracted":8, "obfuscation_flag":false, "bytes":64}`}
                 </code>
              </div>
           </div>
        </div>

        {/* Philosophy & AI */}
        <div className="grid grid-cols-2 gap-6">
           <div className="bg-white border border-gray-200 rounded-2xl p-6 shadow-sm">
              <div className="text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-2 flex items-center gap-2"><ShieldCheck className="w-4 h-4 text-gray-400" /> CORE ARCHITECTURE</div>
              <h3 className="text-xl font-bold text-gray-900 mb-3">Layered Detection Philosophy</h3>
              <p className="text-sm text-gray-600 mb-6 leading-relaxed">
                 Single-source defenses routinely fail against zero-day phishing kits and deceptive lookalike domains. Modern adversaries routinely spin up throwaway subdomains, cycle through dynamic DNS providers within hours, and bypass basic blocklists.
              </p>
              <div className="grid grid-cols-2 gap-4">
                 <div className="bg-red-50 border border-red-100 rounded-xl p-4">
                    <h4 className="text-xs font-bold text-red-900 flex items-center gap-1 mb-2"><EyeOff className="w-3 h-3 text-red-500" /> Static Blocklists</h4>
                    <p className="text-[10px] text-red-800 leading-relaxed">Blind to attacks created less than 4 hours ago. Cannot defend against instant homoglyphs or fast-flux networks.</p>
                 </div>
                 <div className="bg-blue-50 border border-blue-100 rounded-xl p-4">
                    <h4 className="text-xs font-bold text-blue-900 flex items-center gap-1 mb-2"><Activity className="w-3 h-3 text-blue-500" /> ScamShield Synthesis</h4>
                    <p className="text-[10px] text-blue-800 leading-relaxed">Cross-validates 24 structural indicators, MX/SPF posture, WHOIS age delta, and semantic brand mimicry.</p>
                 </div>
              </div>
           </div>
           
           <div className="bg-white border border-gray-200 rounded-2xl p-6 shadow-sm">
              <div className="text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-2 flex items-center gap-2"><Zap className="w-4 h-4 text-gray-400" /> INTERPRETABLE AI</div>
              <h3 className="text-xl font-bold text-gray-900 mb-3">Why Explanations Matter</h3>
              <p className="text-sm text-gray-600 mb-6 leading-relaxed">
                 Security analysts and employees cannot act effectively on a naked confidence percentage (i.e. Score: 0.87). Unexplained scores generate alert fatigue and distrust. ScamShield decomposes risk into plain language forensic narratives.
              </p>
              <div className="bg-gray-50 border border-gray-200 rounded-xl p-4 shadow-inner">
                 <div className="flex items-center justify-between border-b border-gray-200 pb-2 mb-3">
                    <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Forensic Rationale Card</span>
                    <span className="text-[10px] font-bold text-red-600 uppercase tracking-wider bg-red-100 px-2 py-0.5 rounded">High Risk Detected</span>
                 </div>
                 <ul className="space-y-2">
                    <li className="flex items-start gap-2 text-xs text-gray-700"><AlertTriangle className="w-3.5 h-3.5 text-red-500 flex-shrink-0 mt-0.5" /> <span><strong>Lookalike domain target:</strong> Mimics trusted banking brand using Cyrillic homoglyph (a vs а).</span></li>
                    <li className="flex items-start gap-2 text-xs text-gray-700"><RefreshCcw className="w-3.5 h-3.5 text-yellow-500 flex-shrink-0 mt-0.5" /> <span><strong>Suspicious redirect chain:</strong> 3 chained hops through newly registered ephemeral dynamic DNS gateways.</span></li>
                    <li className="flex items-start gap-2 text-xs text-gray-700"><Clock className="w-3.5 h-3.5 text-gray-400 flex-shrink-0 mt-0.5" /> <span><strong>Domain Age:</strong> Registered 18 minutes prior to inspection via anonymous registrar.</span></li>
                 </ul>
              </div>
           </div>
        </div>
      </div>
    </div>
  );
}
