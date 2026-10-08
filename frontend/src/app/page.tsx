import Link from "next/link";
import { ArrowRight, Check, FileText, Link2, QrCode, ShieldCheck } from "lucide-react";

const capabilities = [
  { number: "01", icon: Link2, title: "URL ANALYSIS", text: "Rules and machine learning examine suspicious URL patterns, canonical structures, and security signals." },
  { number: "02", icon: FileText, title: "MESSAGE SCANNING", text: "Extract and evaluate links from complete SMS, email, or chat messages." },
  { number: "03", icon: QrCode, title: "QR PROTECTION", text: "Decode QR codes locally and inspect their destination without opening the link." },
];

export default function LandingPage() {
  return (
    <main>
      <section className="mx-auto grid max-w-7xl items-center gap-14 px-6 pb-20 pt-20 lg:grid-cols-[1.05fr_.95fr]">
        <div>
          <div className="mb-7 inline-flex rounded-full border border-slate-200 bg-white px-3 py-1 font-mono text-[10px] tracking-widest text-slate-500">● v2.4 SEC ENGINE / ZERO-CLIENT EXECUTION SANDBOX</div>
          <h1 className="max-w-2xl text-5xl font-bold leading-[1.03] tracking-[-0.04em] text-slate-950 md:text-7xl">Know where a link leads before you click.</h1>
          <p className="mt-7 max-w-xl text-lg leading-8 text-slate-600">ScamShield analyzes URLs, messages, and QR codes for phishing and scam signals — and explains why something looks dangerous.</p>
          <div className="mt-8 flex gap-3">
            <Link href="/scanner" className="inline-flex items-center gap-2 rounded-md bg-slate-950 px-5 py-3 text-sm font-semibold text-white hover:bg-slate-800">Scan a link <ArrowRight className="h-4 w-4" /></Link>
            <Link href="#how-it-works" className="rounded-md border border-slate-300 bg-white px-5 py-3 text-sm font-semibold text-slate-700 hover:bg-slate-50">See how it works</Link>
          </div>
          <p className="mt-4 font-mono text-[10px] text-slate-500">✓ No account required to get started.</p>
        </div>
        <div className="rounded-xl border border-slate-300 bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between border-b border-slate-200 pb-4 font-mono text-[10px] text-slate-500"><span>SCAN RESULT · DEMO PREVIEW</span><span className="rounded-full border border-amber-200 bg-amber-50 px-2 py-1 text-amber-700">SUSPICIOUS</span></div>
          <div className="py-5"><div className="flex items-end gap-2"><strong className="text-5xl text-orange-700">68.6</strong><span className="pb-2 font-mono text-xs text-slate-500">/ 100</span></div><p className="mt-2 font-semibold text-slate-900">Potential phishing attempt</p><p className="text-xs text-slate-500">High likelihood similarity to institutional gateway.</p></div>
          <div className="space-y-2">{["Brand impersonation", "Credential harvesting language", "Suspicious domain structure"].map((item) => <div key={item} className="rounded-md border border-slate-200 p-3 text-xs"><span className="font-semibold text-slate-800">△ {item}</span><p className="mt-1 text-slate-500">Evidence identified by the analysis pipeline.</p></div>)}</div>
          <p className="mt-4 font-mono text-[10px] text-slate-500">Marketing preview — run a scan for a real report.</p>
        </div>
      </section>

      <section className="mx-auto grid max-w-7xl gap-4 px-6 pb-20 md:grid-cols-3">{capabilities.map(({ number, icon: Icon, title, text }) => <div key={title} className="rounded-xl border border-slate-200 bg-white p-6"><div className="flex justify-between"><Icon className="h-5 w-5 text-slate-500" /><span className="font-mono text-xs text-slate-400">{number}</span></div><h2 className="mt-8 text-sm font-bold">{title}</h2><p className="mt-3 text-sm leading-6 text-slate-500">{text}</p></div>)}</section>

      <section id="how-it-works" className="mx-auto max-w-7xl px-6 py-16"><p className="font-mono text-[10px] tracking-widest text-slate-500">METHODOLOGY</p><h2 className="mt-2 text-4xl font-bold tracking-tight">How it works</h2><p className="mt-2 text-slate-600">A layered analysis pipeline designed to give you evidence, not just an answer.</p><div className="mt-10 grid gap-4 md:grid-cols-3">{["Paste or scan", "ScamShield analyzes", "Understand the risk"].map((title, index) => <div key={title} className="rounded-xl border border-slate-200 bg-white p-6"><span className="font-mono text-3xl text-slate-300">0{index + 1}</span><h3 className="mt-6 font-semibold">{title}</h3><p className="mt-3 text-sm leading-6 text-slate-500">{["Submit a URL, message, or QR code without opening its destination.", "Deterministic rules, machine learning, and available intelligence evaluate the input.", "Review the verdict, risk score, and evidence behind the result."][index]}</p></div>)}</div></section>

      <section className="bg-slate-950 text-white"><div className="mx-auto max-w-7xl px-6 py-16"><p className="font-mono text-[10px] tracking-widest text-slate-400">ARCHITECTURE & HARDENING</p><h2 className="mt-3 max-w-2xl text-4xl font-bold tracking-tight">Built to inspect suspicious links without opening them.</h2><div className="mt-10 grid gap-3 md:grid-cols-3">{["Bounded redirect analysis", "SSRF and DNS rebinding protection", "QR decoding without navigation", "Validated TLS connections", "Security-focused backend"].map((item) => <div key={item} className="flex gap-3 rounded-lg border border-slate-700 bg-slate-900 p-4 text-sm text-slate-300"><Check className="h-4 w-4 shrink-0 text-emerald-400" />{item}</div>)}</div></div></section>

      <section className="mx-auto max-w-7xl px-6 py-24 text-center"><ShieldCheck className="mx-auto h-8 w-8 text-slate-500" /><h2 className="mt-4 text-4xl font-bold tracking-tight">Check the link before you trust it.</h2><p className="mt-3 text-slate-600">Scan a URL, complete message, or QR image through ScamShield.</p><Link href="/scanner" className="mt-7 inline-flex items-center gap-2 rounded-md bg-slate-950 px-5 py-3 text-sm font-semibold text-white">Start scanning <ArrowRight className="h-4 w-4" /></Link><p className="mt-3 font-mono text-[10px] text-slate-500">No account required to get started.</p></section>
    </main>
  );
}
