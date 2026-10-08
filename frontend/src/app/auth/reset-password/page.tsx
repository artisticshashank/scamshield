"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";
import { supabase } from "@/lib/supabase";

export default function ResetPasswordPage() {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!supabase) return setError("Authentication is not configured.");
    if (password.length < 8 || password !== confirm) return setError(password !== confirm ? "Passwords do not match." : "Use at least 8 characters.");
    const result = await supabase.auth.updateUser({ password });
    if (result.error) return setError(result.error.message);
    router.push("/auth/login");
  }
  return <main className="mx-auto max-w-md px-6 py-16"><div className="rounded-xl border border-slate-200 bg-white p-8 shadow-sm"><h1 className="text-2xl font-bold">Choose a new password</h1><form onSubmit={submit} className="mt-7 space-y-4"><input required minLength={8} type="password" placeholder="New password" value={password} onChange={(event) => setPassword(event.target.value)} className="w-full rounded-md border border-slate-200 p-3" /><input required type="password" placeholder="Confirm password" value={confirm} onChange={(event) => setConfirm(event.target.value)} className="w-full rounded-md border border-slate-200 p-3" />{error && <p role="alert" className="text-sm text-red-600">{error}</p>}<button className="w-full rounded-md bg-slate-950 p-3 font-semibold text-white">Update password</button></form></div></main>;
}
