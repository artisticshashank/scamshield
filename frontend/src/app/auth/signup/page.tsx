"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Eye, EyeOff, ShieldCheck } from "lucide-react";
import { supabase } from "@/lib/supabase";

export default function SignupPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!supabase) return setError("Authentication is not configured.");
    if (password.length < 8) return setError("Use at least 8 characters.");
    if (password !== confirm) return setError("Passwords do not match.");
    setLoading(true); setError(null);
    const { data, error: authError } = await supabase.auth.signUp({ email, password });
    setLoading(false);
    if (authError) return setError(authError.message);
    if (!data.session) { setSent(true); return; }
    router.push("/");
  }
  return <main className="mx-auto max-w-md px-6 py-16"><div className="rounded-xl border border-slate-200 bg-white p-8 shadow-sm"><div className="mx-auto flex h-10 w-10 items-center justify-center rounded-lg bg-slate-100"><ShieldCheck className="h-5 w-5" /></div><h1 className="mt-5 text-center text-2xl font-bold">Create your ScamShield account</h1><p className="mt-2 text-center text-sm text-slate-500">Save scan history and continue investigations across sessions.</p>{sent ? <div className="mt-8 rounded-lg bg-slate-50 p-5 text-center"><h2 className="font-semibold">Check your email</h2><p className="mt-2 text-sm text-slate-600">We sent a verification link to {email}.</p><Link href="/auth/login" className="mt-5 inline-block text-sm font-semibold underline">Back to sign in</Link></div> : <form onSubmit={submit} className="mt-7 space-y-4"><label className="block text-sm font-medium">Email address<input required type="email" value={email} onChange={e => setEmail(e.target.value)} className="mt-2 w-full rounded-md border border-slate-200 p-3 outline-none focus:border-slate-500" /></label><label className="block text-sm font-medium">Password<div className="relative mt-2"><input required minLength={8} type={showPassword ? "text" : "password"} value={password} onChange={e => setPassword(e.target.value)} className="w-full rounded-md border border-slate-200 p-3 pr-10 outline-none focus:border-slate-500" /><button type="button" aria-label="Toggle password visibility" onClick={() => setShowPassword(!showPassword)} className="absolute right-3 top-3 text-slate-400">{showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button></div></label><label className="block text-sm font-medium">Confirm password<input required type="password" value={confirm} onChange={e => setConfirm(e.target.value)} className="mt-2 w-full rounded-md border border-slate-200 p-3 outline-none focus:border-slate-500" /></label>{error && <p role="alert" className="text-sm text-red-600">{error}</p>}<button disabled={loading} className="w-full rounded-md bg-slate-950 p-3 font-semibold text-white disabled:opacity-50">{loading ? "Creating account..." : "Create account →"}</button><p className="text-center text-sm text-slate-500">Already have an account? <Link href="/auth/login" className="font-semibold text-slate-900 underline">Sign in →</Link></p></form>}</div></main>;
}
