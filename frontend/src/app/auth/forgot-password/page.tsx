"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";
import { supabase } from "@/lib/supabase";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!supabase) return setError("Authentication is not configured.");
    const result = await supabase.auth.resetPasswordForEmail(email, { redirectTo: `${window.location.origin}/auth/reset-password` });
    if (result.error) return setError(result.error.message);
    setSent(true);
  }
  return <main className="mx-auto max-w-md px-6 py-16"><div className="rounded-xl border border-slate-200 bg-white p-8 shadow-sm"><h1 className="text-2xl font-bold">Reset your password</h1>{sent ? <><p className="mt-3 text-sm text-slate-600">Check your email for a secure password reset link.</p><Link href="/auth/login" className="mt-6 inline-block text-sm font-semibold underline">Back to sign in</Link></> : <form onSubmit={submit} className="mt-7 space-y-4"><label className="block text-sm font-medium">Email address<input required type="email" value={email} onChange={(event) => setEmail(event.target.value)} className="mt-2 w-full rounded-md border border-slate-200 p-3" /></label>{error && <p role="alert" className="text-sm text-red-600">{error}</p>}<button className="w-full rounded-md bg-slate-950 p-3 font-semibold text-white">Send reset link</button><Link href="/auth/login" className="block text-center text-sm underline">Back to sign in</Link></form>}</div></main>;
}
