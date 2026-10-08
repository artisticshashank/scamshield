import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { AuthProvider } from "@/components/AuthProvider";
import { AppChrome } from "@/components/AppChrome";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "ScamShield | Sec Ops",
  description: "Enterprise Scam & Threat Inspector",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${inter.className} bg-[#f9fafb] text-slate-900`} suppressHydrationWarning>
        <AuthProvider><AppChrome>{children}</AppChrome></AuthProvider>
      </body>
    </html>
  );
}
