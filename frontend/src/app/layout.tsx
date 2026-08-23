/**
 * ThreatLens AI — Root Layout
 * Sets up fonts, metadata, and the global navigation shell
 */

import type { Metadata, Viewport } from "next";
import "./globals.css";
import { Navbar } from "@/components/Navbar";
import { Toaster } from "@/components/ui/toaster";
import { DetectiveCharacter } from "@/components/DetectiveCharacter";
import { AmbientScanEffect } from "@/components/ThreatDetectionAnimation";

export const metadata: Metadata = {
  title: {
    default: "ThreatLens AI — Cybersecurity Intelligence Platform",
    template: "%s | ThreatLens AI",
  },
  description:
    "Real-time AI-powered threat detection, classification, and response platform for security operations teams.",
  keywords: ["cybersecurity", "threat intelligence", "SOC", "incident response", "AI security"],
  authors: [{ name: "ThreatLens AI Team" }],
  robots: { index: false, follow: false }, // Internal tool — no indexing
  icons: { icon: "/favicon.ico" },
};

export const viewport: Viewport = {
  themeColor: "#020817",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <head>
        {/* Preconnect to Google Fonts for faster load */}
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
      </head>
      <body className="min-h-screen grid-bg">
        {/* Global cyber grid background */}
        <div className="relative flex flex-col min-h-screen">
          <Navbar />
          <main className="flex-1 container mx-auto px-4 py-6 max-w-7xl">
            {children}
          </main>
          <footer className="border-t border-white/5 py-4 text-center text-xs text-muted-foreground">
            <span className="terminal-text">ThreatLens AI</span>
            {" "}v1.0.0 — Security Operations Platform
          </footer>
        </div>
        <AmbientScanEffect className="fixed inset-0 pointer-events-none z-0" />
        <DetectiveCharacter
          className="fixed z-50"
          initialPosition={{ x: 5, y: 85 }}
        />
        <Toaster />
      </body>
    </html>
  );
}
