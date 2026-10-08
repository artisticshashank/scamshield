"use client";

import { useState } from "react";
import { useEffect } from "react";
import { Download, Plus, Search, Filter, ShieldAlert, Clock, Link as LinkIcon, MessageSquare, QrCode } from "lucide-react";
import Link from "next/link";
import { formatVerdict, isMessageScan, responseId, selectScan, type ScanResponse } from "@/lib/scamshield";
import { API_BASE_URL } from "@/lib/scamshield";
import { useAuth } from "@/components/AuthProvider";

type HistoryItem = { id: string; response: ScanResponse; saved_at: string };

export default function HistoryPage() {
  const [filter, setFilter] = useState("All");
  const [searchQuery, setSearchQuery] = useState("");
  const { session } = useAuth();
  const [items, setItems] = useState<HistoryItem[]>([]);

  useEffect(() => {
    const raw = window.localStorage.getItem("scamshield.scan_history");
    if (raw) {
      try {
        const localItems = JSON.parse(raw) as HistoryItem[];
        queueMicrotask(() => setItems(localItems));
      } catch {
        queueMicrotask(() => setItems([]));
      }
    }
    if (!session) return;
    void fetch(`${API_BASE_URL}/history`, {
      headers: { Authorization: `Bearer ${session.access_token}` },
    }).then(async (response) => {
      if (!response.ok) return;
      const body = (await response.json()) as { items: HistoryItem[] };
      queueMicrotask(() => setItems(body.items));
    });
  }, [session]);

  const scans = items.map((item) => {
    const response = item.response;
    const primary = isMessageScan(response) ? response.scan_results[0] : response;
    return {
      id: responseId(response),
      response,
      status: formatVerdict(isMessageScan(response) ? response.overall_verdict : primary?.verdict ?? "safe"),
      target: isMessageScan(response) ? response.original_message : response.original_input,
      score: isMessageScan(response) ? response.overall_risk_score ?? 0 : primary?.risk_score ?? 0,
      source: isMessageScan(response) ? "Message" : "URL",
      time: item.saved_at,
    };
  });

  const filteredScans = scans.filter((scan) => {
    if (filter !== "All" && scan.status !== filter.toUpperCase()) return false;
    if (searchQuery && !scan.target.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="max-w-6xl mx-auto space-y-8 pb-12">
      <header className="flex items-center justify-between border-b border-gray-200 pb-4">
        <div className="text-sm font-semibold text-gray-500 uppercase tracking-widest">
          Sec Ops / <span className="text-gray-900">Scan History</span>
        </div>
      </header>

      <div className="flex items-end justify-between">
        <div>
          <p className="text-[10px] font-mono text-gray-500 mb-2 uppercase tracking-widest font-bold">
            LOGS // TELEMETRY • REAL-TIME ARCHIVE
          </p>
          <h2 className="text-4xl font-extrabold tracking-tight text-gray-900">
            Scan History
          </h2>
          <p className="text-gray-600 mt-2 max-w-2xl text-lg font-medium">
            Review previously analyzed links, SMS snippets, and decrypted QR payloads evaluated by ScamShield engine v2.4.1.
          </p>
        </div>
        <div className="flex gap-3">
          <button className="flex items-center gap-2 px-4 py-2 bg-white border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 font-bold text-sm shadow-sm transition-colors">
            <Download className="w-4 h-4" />
            Export CSV
          </button>
          <button className="flex items-center gap-2 px-4 py-2 bg-gray-900 text-white rounded-lg hover:bg-gray-800 font-bold text-sm shadow-sm transition-colors">
            <Plus className="w-4 h-4" />
            New Inspection
          </button>
        </div>
      </div>

      <div className="grid grid-cols-4 gap-4">
        <div className="bg-white border border-gray-200 p-5 rounded-xl shadow-sm relative overflow-hidden">
          <div className="text-gray-500 text-[10px] font-bold uppercase mb-2 tracking-widest flex items-center justify-between">
            Total Processed <ActivityIcon className="w-4 h-4 text-gray-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-gray-900">{items.length}</span>
            <span className="text-sm text-gray-500 font-bold">local browser history</span>
          </div>
        </div>
        <div className="bg-white border border-gray-200 p-5 rounded-xl shadow-sm">
          <div className="text-gray-500 text-[10px] font-bold uppercase mb-2 tracking-widest flex items-center justify-between">
            High Threat Hits <ShieldAlert className="w-4 h-4 text-red-500" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-red-600">{scans.filter((scan) => scan.status === "DANGEROUS").length}</span>
            <span className="text-sm text-gray-500 font-bold">dangerous</span>
          </div>
        </div>
        <div className="bg-white border border-gray-200 p-5 rounded-xl shadow-sm">
          <div className="text-gray-500 text-[10px] font-bold uppercase mb-2 tracking-widest flex items-center justify-between">
            Suspicious / Quarantined <ShieldAlert className="w-4 h-4 text-blue-500" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-gray-900">{scans.filter((scan) => scan.status === "SUSPICIOUS").length}</span>
            <span className="text-sm text-gray-500 font-bold">suspicious</span>
          </div>
        </div>
        <div className="bg-white border border-gray-200 p-5 rounded-xl shadow-sm">
          <div className="text-gray-500 text-[10px] font-bold uppercase mb-2 tracking-widest flex items-center justify-between">
            Average Evaluation Time <Clock className="w-4 h-4 text-gray-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-gray-900">—</span>
            <span className="text-[10px] font-mono text-gray-500 font-bold">not reported by API</span>
          </div>
        </div>
      </div>

      <div className="bg-white border border-gray-200 rounded-xl shadow-sm overflow-hidden">
        <div className="p-4 border-b border-gray-200 flex items-center justify-between bg-gray-50">
          <div className="flex items-center gap-2 p-1 bg-gray-200/50 rounded-lg border border-gray-200">
            {['All', 'Safe', 'Suspicious', 'Dangerous'].map(tab => (
              <button 
                key={tab}
                onClick={() => setFilter(tab)}
                className={`px-4 py-1.5 text-sm font-bold rounded-md shadow-sm transition-colors ${
                  filter === tab ? 'bg-gray-900 text-white' : 'text-gray-600 hover:text-gray-900 hover:bg-gray-200/50'
                }`}
              >
                {tab} <span className="opacity-50">({tab === "All" ? scans.length : scans.filter((scan) => scan.status === tab.toUpperCase()).length})</span>
              </button>
            ))}
          </div>
          <div className="flex items-center gap-3">
            <div className="relative">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
              <input 
                type="text" 
                placeholder="Search domain, payload or CIDR..." 
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9 pr-4 py-2 bg-white border border-gray-300 rounded-lg text-sm w-72 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all font-mono placeholder:font-sans placeholder:text-gray-400 font-medium text-gray-900"
              />
            </div>
            <button className="p-2 border border-gray-300 bg-white rounded-lg text-gray-500 hover:bg-gray-50 hover:text-gray-700 shadow-sm transition-colors">
              <Filter className="w-4 h-4" />
            </button>
          </div>
        </div>

        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-gray-50 border-b border-gray-200 text-[10px] font-bold text-gray-500 uppercase tracking-widest">
              <th className="px-6 py-4">Status</th>
              <th className="px-6 py-4">Target / Payload Snippet</th>
              <th className="px-6 py-4">Threat Score</th>
              <th className="px-6 py-4">Source</th>
              <th className="px-6 py-4">Timestamp</th>
              <th className="px-6 py-4 text-right">Forensics</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {filteredScans.length > 0 ? filteredScans.map((scan) => (
              <tr key={scan.id} className="hover:bg-gray-50 transition-colors group">
                <td className="px-6 py-4">
                  <span className={`inline-flex items-center gap-2 px-2.5 py-1 rounded border text-[10px] font-extrabold uppercase tracking-widest ${
                    scan.status === 'DANGEROUS' ? 'bg-red-50 text-red-700 border-red-200' :
                    scan.status === 'SUSPICIOUS' ? 'bg-blue-50 text-blue-700 border-blue-200' :
                    'bg-green-50 text-green-700 border-green-200'
                  }`}>
                    <span className={`w-2 h-2 rounded-full ${
                      scan.status === 'DANGEROUS' ? 'bg-red-500 shadow-[0_0_4px_rgba(239,68,68,0.8)]' :
                      scan.status === 'SUSPICIOUS' ? 'bg-blue-500 shadow-[0_0_4px_rgba(59,130,246,0.8)]' :
                      'bg-green-500 shadow-[0_0_4px_rgba(34,197,94,0.8)]'
                    }`}></span>
                    {scan.status}
                  </span>
                </td>
                <td className="px-6 py-4 font-mono text-sm text-gray-900 font-bold">
                  {scan.target}
                </td>
                <td className="px-6 py-4">
                  <div className="flex items-center gap-3">
                    <span className={`text-sm font-extrabold ${
                      scan.score >= 90 ? 'text-red-600' : scan.score >= 50 ? 'text-blue-600' : 'text-green-600'
                    }`}>{scan.score}</span>
                    <div className="w-16 h-1.5 bg-gray-200 rounded-full overflow-hidden border border-gray-300">
                      <div className={`h-full rounded-full ${
                        scan.score >= 90 ? 'bg-red-500' : scan.score >= 50 ? 'bg-blue-500' : 'bg-green-500'
                      }`} style={{ width: `${scan.score}%` }}></div>
                    </div>
                  </div>
                </td>
                <td className="px-6 py-4">
                  <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest text-gray-600 bg-gray-100 border border-gray-200 px-2.5 py-1 rounded w-fit">
                    {scan.source === 'Message' && <MessageSquare className="w-3.5 h-3.5" />}
                    {scan.source === 'URL' && <LinkIcon className="w-3.5 h-3.5" />}
                    {scan.source === 'QR Code' && <QrCode className="w-3.5 h-3.5" />}
                    {scan.source}
                  </div>
                </td>
                <td className="px-6 py-4 text-xs font-semibold text-gray-500">
                  {new Date(scan.time).toLocaleString()}
                </td>
                <td className="px-6 py-4 text-right">
                  <Link href={selectScan(scan.id)} className="text-sm font-bold text-gray-900 hover:text-blue-600 flex items-center justify-end gap-1 group-hover:underline">
                    View Analysis <span className="text-gray-400">→</span>
                  </Link>
                </td>
              </tr>
            )) : (
              <tr>
                <td colSpan={6} className="px-6 py-12 text-center text-sm font-medium text-gray-500">
                  No scans found matching your criteria.
                </td>
              </tr>
            )}
          </tbody>
        </table>

        <div className="px-6 py-4 border-t border-gray-200 flex items-center justify-between text-sm text-gray-500 bg-gray-50">
          <span className="font-medium">Showing <strong className="text-gray-900">{filteredScans.length ? `1-${filteredScans.length}` : "0"}</strong> of <strong className="text-gray-900">{filteredScans.length}</strong> recorded scans</span>
          <div className="flex gap-1">
            <button className="px-2 py-1 text-gray-400 hover:text-gray-900 font-bold">&lt;</button>
            <button className="px-3 py-1 bg-gray-900 text-white rounded font-bold shadow-sm">1</button>
            <button className="px-3 py-1 hover:bg-gray-200 text-gray-600 rounded font-bold transition-colors">2</button>
            <button className="px-3 py-1 hover:bg-gray-200 text-gray-600 rounded font-bold transition-colors">3</button>
            <span className="px-2 py-1 text-gray-400">...</span>
            <button className="px-3 py-1 hover:bg-gray-200 text-gray-600 rounded font-bold transition-colors">7</button>
            <button className="px-2 py-1 hover:text-gray-900 font-bold text-gray-600">&gt;</button>
          </div>
        </div>
      </div>
    </div>
  );
}

function ActivityIcon(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg {...props} fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
    </svg>
  );
}
