"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield, LogOut } from "lucide-react";
import { Sidebar } from "@/components/Sidebar";
import { useAuth } from "@/components/AuthProvider";

export function AppChrome({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { user, signOut } = useAuth();
  const publicPage = pathname === "/" || pathname.startsWith("/auth/");

  if (!publicPage) {
    return (
      <div className="flex min-h-screen">
        <Sidebar />
        <main className="flex-1 ml-64 p-8">{children}</main>
      </div>
    );
  }

  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <Link href="/" className="flex items-center gap-2">
            <span className="flex h-7 w-7 items-center justify-center rounded-md bg-slate-950">
              <Shield className="h-4 w-4 text-white" />
            </span>
            <span className="font-bold tracking-tight">SCAMSHIELD</span>
            <span className="rounded bg-slate-100 px-2 py-1 font-mono text-[9px] tracking-widest text-slate-500">SEC OPS</span>
          </Link>
          <nav className="hidden items-center gap-7 text-sm text-slate-600 md:flex">
            <Link href="/scanner" className="hover:text-slate-950">Scanner</Link>
            <Link href="/#how-it-works" className="hover:text-slate-950">How it works</Link>
            <Link href="/about" className="hover:text-slate-950">About</Link>
          </nav>
          <div className="flex items-center gap-2">
            {user ? (
              <>
                <Link href="/history" className="hidden text-sm text-slate-600 hover:text-slate-950 md:block">History</Link>
                <button onClick={() => void signOut()} className="flex items-center gap-2 rounded-md border border-slate-200 px-3 py-2 text-xs font-semibold hover:bg-slate-50">
                  <span className="max-w-28 truncate">{user.email}</span><LogOut className="h-3.5 w-3.5" />
                </button>
              </>
            ) : (
              <>
                <Link href="/auth/login" className="rounded-md border border-slate-200 px-3 py-2 text-xs font-semibold hover:bg-slate-50">Sign in</Link>
                <Link href="/auth/signup" className="rounded-md bg-slate-950 px-3 py-2 text-xs font-semibold text-white hover:bg-slate-800">Get started</Link>
              </>
            )}
          </div>
        </div>
      </header>
      {children}
    </div>
  );
}
