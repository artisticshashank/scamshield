"use client";

import type { MessageScanRecord, ScanRecord, ScanResponse } from "@/lib/scamshield";

export type DemoCategory = "SAFE" | "SUSPICIOUS" | "DANGEROUS";
export type DemoSample = {
  id: string;
  category: DemoCategory;
  title: string;
  url: string;
  message: string;
  score: number;
};

export const demoSamples: DemoSample[] = [
  // SAFE — official public destinations and neutral messages
  { id: "safe-01", category: "SAFE", title: "Python documentation", url: "https://www.python.org/", message: "I found the official Python website. Documentation and downloads are available here: https://www.python.org/", score: 5 },
  { id: "safe-02", category: "SAFE", title: "MDN Web Docs", url: "https://developer.mozilla.org/", message: "For web development reference, use the MDN Web Docs: https://developer.mozilla.org/", score: 7 },
  { id: "safe-03", category: "SAFE", title: "Wikimedia", url: "https://www.wikimedia.org/", message: "Wikimedia's official site is available at https://www.wikimedia.org/ for information about its projects.", score: 8 },
  { id: "safe-04", category: "SAFE", title: "GitHub", url: "https://github.com/", message: "You can find public source-code repositories on the official GitHub website: https://github.com/", score: 6 },
  { id: "safe-05", category: "SAFE", title: "Node.js", url: "https://nodejs.org/", message: "The official Node.js website provides downloads and guides: https://nodejs.org/", score: 9 },
  { id: "safe-06", category: "SAFE", title: "React", url: "https://react.dev/", message: "The React documentation is published at its official website: https://react.dev/", score: 8 },
  { id: "safe-07", category: "SAFE", title: "Kubernetes", url: "https://kubernetes.io/", message: "The Kubernetes project documentation can be read at https://kubernetes.io/", score: 10 },
  { id: "safe-08", category: "SAFE", title: "Django", url: "https://www.djangoproject.com/", message: "For official Django project information, visit https://www.djangoproject.com/", score: 7 },
  { id: "safe-09", category: "SAFE", title: "NVIDIA", url: "https://www.nvidia.com/", message: "NVIDIA's public website is https://www.nvidia.com/ for product and company information.", score: 12 },
  { id: "safe-10", category: "SAFE", title: "Government of India", url: "https://www.india.gov.in/", message: "The National Portal of India is available at https://www.india.gov.in/ for public information.", score: 6 },

  // SUSPICIOUS — reserved .example domains; safe, non-routable fixtures
  { id: "susp-01", category: "SUSPICIOUS", title: "Profile review", url: "https://account-review.example/profile", message: "A notification says my profile needs a review. It links to https://account-review.example/profile. I have not verified the sender.", score: 38 },
  { id: "susp-02", category: "SUSPICIOUS", title: "Delivery update", url: "https://parcel-status.example/track?id=4821", message: "A delivery update asks me to check this tracking page: https://parcel-status.example/track?id=4821. I was not expecting a parcel.", score: 42 },
  { id: "susp-03", category: "SUSPICIOUS", title: "Account notice", url: "https://member-notice.example/account", message: "I received an account notice from an unfamiliar sender. The link is https://member-notice.example/account.", score: 35 },
  { id: "susp-04", category: "SUSPICIOUS", title: "Invoice portal", url: "https://invoice-check.example/view/1048", message: "Please review the invoice link sent by an unknown contact: https://invoice-check.example/view/1048.", score: 40 },
  { id: "susp-05", category: "SUSPICIOUS", title: "Subscription alert", url: "https://subscription-help.example/status", message: "A message about my subscription includes this unfamiliar link: https://subscription-help.example/status.", score: 34 },
  { id: "susp-06", category: "SUSPICIOUS", title: "Document share", url: "https://shared-document.example/open/72", message: "Someone I do not recognize shared a document with me: https://shared-document.example/open/72. I will verify the sender first.", score: 41 },
  { id: "susp-07", category: "SUSPICIOUS", title: "Reward information", url: "https://reward-details.example/claim-info", message: "An unexpected message mentions a reward and points to https://reward-details.example/claim-info.", score: 44 },
  { id: "susp-08", category: "SUSPICIOUS", title: "Support request", url: "https://customer-support.example/ticket/218", message: "A support ticket notification came from an unknown sender: https://customer-support.example/ticket/218.", score: 37 },
  { id: "susp-09", category: "SUSPICIOUS", title: "Payment status", url: "https://payment-status.example/check", message: "I was sent a payment status link that I do not recognize: https://payment-status.example/check.", score: 46 },
  { id: "susp-10", category: "SUSPICIOUS", title: "Verification request", url: "https://identity-check.example/continue", message: "An unexpected message asks me to continue an identity check at https://identity-check.example/continue. I need to verify it independently.", score: 48 },

  // DANGEROUS — synthetic .invalid destinations; no live malicious sites
  { id: "danger-01", category: "DANGEROUS", title: "Bank password theft", url: "http://bank-security-alert.invalid/urgent/verify-password", message: "URGENT: Your bank account will be blocked in 10 minutes. Confirm your password and one-time code immediately: http://bank-security-alert.invalid/urgent/verify-password", score: 96 },
  { id: "danger-02", category: "DANGEROUS", title: "Wallet recovery scam", url: "http://crypto-wallet-recovery.invalid/seed-phrase/restore", message: "Your wallet is at risk. Send your 12-word recovery phrase now to restore access: http://crypto-wallet-recovery.invalid/seed-phrase/restore", score: 98 },
  { id: "danger-03", category: "DANGEROUS", title: "Payroll credential theft", url: "http://employee-payroll.invalid/login/credential-confirm", message: "Payroll access expires today. Enter your employee password at this unverified page: http://employee-payroll.invalid/login/credential-confirm", score: 91 },
  { id: "danger-04", category: "DANGEROUS", title: "Fake tax refund", url: "http://tax-refund-release.invalid/claim/bank-details", message: "Final warning: claim your tax refund by entering bank details and card PIN here: http://tax-refund-release.invalid/claim/bank-details", score: 94 },
  { id: "danger-05", category: "DANGEROUS", title: "Remote access scam", url: "http://device-security-fix.invalid/download/remote-control", message: "Your device is infected. Install this unknown remote-control tool and share the access code: http://device-security-fix.invalid/download/remote-control", score: 93 },
  { id: "danger-06", category: "DANGEROUS", title: "Gift card fraud", url: "http://corporate-gift-validation.invalid/redeem/secret-code", message: "You won a gift card. Reveal the scratch-card PIN and redeem it immediately: http://corporate-gift-validation.invalid/redeem/secret-code", score: 89 },
  { id: "danger-07", category: "DANGEROUS", title: "One-time code theft", url: "http://secure-otp-confirm.invalid/session/unlock", message: "A support agent needs your one-time password to unlock your account. Submit it here now: http://secure-otp-confirm.invalid/session/unlock", score: 97 },
  { id: "danger-08", category: "DANGEROUS", title: "Fake payment reversal", url: "http://payment-reversal.invalid/refund/card-pin", message: "Your payment reversal failed. Enter your full card number, CVV and PIN to receive the refund: http://payment-reversal.invalid/refund/card-pin", score: 95 },
  { id: "danger-09", category: "DANGEROUS", title: "Impersonated IT desk", url: "http://company-it-reset.invalid/password/override", message: "IT SECURITY: Your mailbox will be deleted. Override your password immediately at http://company-it-reset.invalid/password/override", score: 92 },
  { id: "danger-10", category: "DANGEROUS", title: "Fake parcel fee", url: "http://parcel-customs-release.invalid/pay/urgent-fee", message: "Your parcel is held. Pay this urgent customs fee with your card details to release it: http://parcel-customs-release.invalid/pay/urgent-fee", score: 90 },
];

export function buildDemoResponse(sample: DemoSample, mode: "url" | "message"): ScanResponse {
  const recommendation =
    sample.category === "SAFE"
      ? "Demo fixture: this example is labelled SAFE for presentation purposes. Always verify the destination independently."
      : sample.category === "SUSPICIOUS"
        ? "Demo fixture: treat this unverified link cautiously and confirm the sender through an independent channel."
        : "Demo fixture: do not open this synthetic link or share passwords, PINs, recovery phrases or one-time codes.";

  const base: ScanRecord = {
    scan_id: `demo-${sample.id}-${mode}`,
    input_type: mode,
    original_input: mode === "url" ? sample.url : sample.message,
    verdict: sample.category,
    risk_score: sample.score,
    recommendation,
    timestamp: new Date().toISOString(),
    evidence: [],
    triggered_rules: [],
    metadata: {
      demo_mode: true,
      demo_fixture_id: sample.id,
      demo_category: sample.category,
      demo_result_type: mode,
    },
  };

  if (mode === "url") return base;

  const urlRecord: ScanRecord = {
    ...base,
    input_type: "url",
    original_input: sample.url,
  };
  const messageResponse: MessageScanRecord = {
    input_type: "message",
    original_message: sample.message,
    extracted_urls: [sample.url],
    scan_results: [urlRecord],
    overall_verdict: sample.category,
    overall_risk_score: sample.score,
    recommendation,
    metadata: {
      demo_mode: true,
      demo_fixture_id: sample.id,
      demo_category: sample.category,
      demo_result_type: mode,
    },
  };
  return messageResponse;
}
