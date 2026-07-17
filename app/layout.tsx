import type { Metadata } from "next";
import { JetBrains_Mono, Inter } from "next/font/google";
import "./globals.css";

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-mono",
  subsets: ["latin"],
  weight: ["300", "400", "500", "600", "700"],
  display: "swap",
});

const inter = Inter({
  variable: "--font-sans",
  subsets: ["latin"],
  weight: ["300", "400", "500", "600", "700"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "SENTINEL — AI Security Layer for the Agentic Internet",
  description:
    "Multi-agent cybersecurity platform. Real-time threat detection, sandbox browser isolation, and Civic AI governance. The security layer every AI agent needs.",
  keywords: ["AI security", "agent security", "OKX.AI", "cyber defense", "sandbox scanning", "threat detection"],
  openGraph: {
    title:       "SENTINEL — AI Security Layer for the Agentic Internet",
    description: "Protect any AI agent from phishing, wallet drainers, and DDoS. One API call.",
    type:        "website",
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${jetbrainsMono.variable} ${inter.variable}`}>
      <body>{children}</body>
    </html>
  );
}
