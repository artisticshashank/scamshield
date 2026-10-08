"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield, Target, History, Code, ShieldAlert, Settings } from "lucide-react";

export function Sidebar() {
  const pathname = usePathname();

  const navItems = [
    { name: "Scanner", href: "/scanner", icon: Target },
    { name: "History", href: "/history", icon: History },
    { name: "API", href: "/api-docs", icon: Code },
    { name: "About", href: "/about", icon: ShieldAlert },
  ];

  return (
    <div className="w-64 h-screen border-r border-gray-200 bg-white flex flex-col justify-between fixed left-0 top-0 z-50 shadow-[1px_0_0_0_rgba(0,0,0,0.05)]">
      <div>
        <div className="flex items-center gap-3 p-6 mb-2">
          <div className="w-8 h-8 rounded-lg bg-[#0F172A] flex items-center justify-center">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="font-bold text-base tracking-tight text-gray-900 leading-tight">SCAMSHIELD</h1>
            <p className="text-[10px] text-gray-500 font-mono tracking-widest font-semibold uppercase mt-0.5">SEC OPS</p>
          </div>
        </div>
        
        <nav className="px-4 space-y-1">
          {navItems.map((item) => {
            const isActive = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href));
            const Icon = item.icon;
            return (
              <Link
                key={item.name}
                href={item.href}
                className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-semibold transition-all ${
                  isActive
                    ? "bg-[#0F172A] text-white shadow-sm"
                    : "text-gray-600 hover:bg-gray-100 hover:text-gray-900"
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? "text-white" : "text-gray-500"}`} />
                {item.name}
              </Link>
            );
          })}
        </nav>
      </div>

      <div className="p-4 space-y-2">
        <div className="flex items-center justify-between px-3 py-2 bg-gray-100/80 rounded-full border border-gray-200/50">
          <div className="flex items-center gap-2 text-[10px] font-bold text-gray-600 uppercase tracking-widest">
            <span className="w-2 h-2 rounded-full bg-green-500 shadow-[0_0_4px_rgba(34,197,94,0.4)]"></span>
            Operational
          </div>
          <span className="text-[10px] font-mono text-gray-500">99.98%</span>
        </div>
        <button className="flex items-center justify-between w-full px-3 py-2 text-gray-600 hover:bg-gray-100 hover:text-gray-900 rounded-lg text-sm font-semibold transition-colors group">
          <div className="flex items-center gap-3">
            <Settings className="w-4 h-4 text-gray-500 group-hover:text-gray-900" />
            Settings
          </div>
          <span className="text-[10px] font-mono text-gray-400 group-hover:text-gray-500">CTRL+,</span>
        </button>
      </div>
    </div>
  );
}
