"use client";

/**
 * ThreatLens AI — File & URL Link Threat Scanner Component
 *
 * Features:
 * - File drag & drop / selection
 * - URL link scanning
 * - Real-time terminal threat dashboard
 * - High-Risk Malware Alert banner
 * - Analyst Response recording
 * - Formatted Incident Report
 * - Classification Detection Trend Analysis
 */

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Upload,
  Link as LinkIcon,
  ShieldAlert,
  AlertTriangle,
  Bell,
  CheckCircle2,
  FileText,
  Loader2,
  Search,
  Zap,
  Activity,
} from "lucide-react";
import { threats as threatsApi } from "@/lib/api";
import type { ScanResultResponse, ThreatStatus } from "@/types";

interface ScannerTabProps {
  onScanComplete?: () => void;
}

export function ScannerTab({ onScanComplete }: ScannerTabProps) {
  const [activeTab, setActiveTab] = useState<"file" | "url">("file");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [urlInput, setUrlInput] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResultResponse | null>(null);
  const [analystStatus, setAnalystStatus] = useState<string>("Under Investigation");
  const [updatingStatus, setUpdatingStatus] = useState(false);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    const targetName =
      activeTab === "file"
        ? selectedFile?.name || "uploaded_file.txt"
        : urlInput || "http://suspicious-malicious-domain.org";

    setScanning(true);
    setScanResult(null);

    try {
      // Simulate scanning delay
      await new Promise((resolve) => setTimeout(resolve, 800));
      const res = await threatsApi.scan(activeTab, targetName);
      setScanResult(res);
      setAnalystStatus(res.analyst_response);
      onScanComplete?.();
    } catch (err) {
      console.error("Scan error", err);
    } finally {
      setScanning(false);
    }
  };

  const handleStatusChange = async (newStatus: ThreatStatus, statusLabel: string) => {
    if (!scanResult) return;
    setUpdatingStatus(true);
    try {
      await threatsApi.update(scanResult.threat_event.id, { status: newStatus });
      setAnalystStatus(statusLabel);
      setScanResult((prev) =>
        prev
          ? {
              ...prev,
              incident_report: { ...prev.incident_report, status: statusLabel },
            }
          : prev
      );
    } catch (e) {
      console.error(e);
    } finally {
      setUpdatingStatus(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* ── Scan Inputs Container ────────────────────────────────────────────── */}
      <div className="glass-card p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-bold flex items-center gap-2">
              <Zap className="w-5 h-5 text-accent" />
              AI Malware & Link Scanner
            </h2>
            <p className="text-xs text-muted-foreground mt-1">
              Upload any file or paste a web URL to analyze threats, generate incident reports, and record response.
            </p>
          </div>
          <div className="flex items-center gap-1 p-1 bg-cyber-900 rounded-lg border border-white/5 text-xs">
            <button
              onClick={() => setActiveTab("file")}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium transition-all ${
                activeTab === "file"
                  ? "bg-accent text-cyber-950 shadow-cyber"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              <Upload className="w-3.5 h-3.5" /> Upload File
            </button>
            <button
              onClick={() => setActiveTab("url")}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium transition-all ${
                activeTab === "url"
                  ? "bg-accent text-cyber-950 shadow-cyber"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              <LinkIcon className="w-3.5 h-3.5" /> Scan Link / URL
            </button>
          </div>
        </div>

        <form onSubmit={handleScan} className="space-y-4">
          {activeTab === "file" ? (
            <div className="border-2 border-dashed border-white/10 rounded-xl p-8 text-center hover:border-accent/40 transition-colors bg-cyber-900/30">
              <input
                type="file"
                id="file-upload"
                onChange={handleFileChange}
                className="hidden"
              />
              <label
                htmlFor="file-upload"
                className="cursor-pointer flex flex-col items-center justify-center space-y-3"
              >
                <div className="w-12 h-12 rounded-full bg-accent/10 border border-accent/30 flex items-center justify-center text-accent">
                  <Upload className="w-6 h-6" />
                </div>
                <div>
                  <p className="text-sm font-medium text-foreground">
                    {selectedFile ? (
                      <span className="text-accent font-semibold">{selectedFile.name}</span>
                    ) : (
                      "Click to browse or drag & drop file here"
                    )}
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Supports .txt, .exe, .pdf, .zip, .doc, .vbs, .py, .apk (Max 500MB)
                  </p>
                </div>
              </label>
            </div>
          ) : (
            <div className="space-y-2">
              <label className="text-xs font-medium text-muted-foreground">
                Paste Website URL to Scan
              </label>
              <div className="relative">
                <LinkIcon className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <input
                  type="url"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder="https://example-suspicious-domain.com/login"
                  required
                  className="w-full pl-10 pr-4 py-3 rounded-xl bg-cyber-900 border border-white/10 text-sm
                             placeholder:text-muted-foreground/40 focus:outline-none focus:ring-1 focus:ring-accent"
                />
              </div>
            </div>
          )}

          <div className="flex justify-end">
            <button
              type="submit"
              disabled={scanning || (activeTab === "file" && !selectedFile && false)}
              className="btn-cyber flex items-center gap-2 px-6 py-2.5 bg-accent text-cyber-950 font-semibold rounded-lg hover:bg-accent-hover disabled:opacity-50"
            >
              {scanning ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" /> Analyzing Threat…
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" /> Start AI Threat Scan
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* ── Scan Output Dashboard & Incident Report ───────────────────────────── */}
      <AnimatePresence>
        {scanResult && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            {/* Terminal Live Output */}
            <div className="glass-card p-6 bg-cyber-950/90 border-accent/30 font-mono text-xs text-foreground space-y-4 shadow-cyber">
              <div className="flex items-center justify-between pb-2 border-b border-white/10 text-muted-foreground">
                <span className="text-accent font-bold">--- Threat Monitoring Dashboard ---</span>
                <span className="text-[10px]">Real-time Event Stream</span>
              </div>

              {/* Table header */}
              <div className="overflow-x-auto">
                <div className="min-w-[600px] grid grid-cols-5 text-muted-foreground pb-2 border-b border-white/5 text-[11px] uppercase tracking-wider">
                  <span>Timestamp</span>
                  <span>Target</span>
                  <span>Classification</span>
                  <span>Confidence</span>
                  <span>Action</span>
                </div>
                <div className="min-w-[600px] grid grid-cols-5 py-2.5 text-accent font-medium items-center">
                  <span>{scanResult.incident_report.timestamp}</span>
                  <span className="truncate pr-2">{scanResult.incident_report.target_name}</span>
                  <span className="text-critical font-bold">{scanResult.incident_report.classification}</span>
                  <span>{scanResult.incident_report.confidence}</span>
                  <span className="text-high">{scanResult.incident_report.action_taken}</span>
                </div>
              </div>

              {/* Alert Banners */}
              <div className="space-y-2 pt-2">
                <div className="p-3 rounded bg-critical/20 border border-critical/40 text-critical font-bold flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 animate-bounce" />
                  {scanResult.alert_message}
                </div>

                <div className="p-2.5 rounded bg-accent/10 border border-accent/20 text-accent flex items-center gap-2">
                  <Bell className="w-4 h-4" />
                  📢 Notification Sent to Analyst!
                </div>

                <div className="p-2.5 rounded bg-medium/10 border border-medium/20 text-medium flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    <Activity className="w-4 h-4" />
                    🔎 Analyst Response Recorded: <strong className="text-foreground">{analystStatus}</strong>
                  </span>

                  {/* Interactive Analyst Response Selector */}
                  <div className="flex items-center gap-1">
                    <span className="text-[10px] text-muted-foreground mr-1">Update Status:</span>
                    <button
                      onClick={() => handleStatusChange("investigating", "Under Investigation")}
                      disabled={updatingStatus}
                      className="px-2 py-0.5 rounded bg-white/10 hover:bg-white/20 text-[10px] transition-colors"
                    >
                      Investigating
                    </button>
                    <button
                      onClick={() => handleStatusChange("contained", "Contained")}
                      disabled={updatingStatus}
                      className="px-2 py-0.5 rounded bg-medium/30 hover:bg-medium/50 text-[10px] text-medium transition-colors"
                    >
                      Contained
                    </button>
                    <button
                      onClick={() => handleStatusChange("resolved", "Resolved")}
                      disabled={updatingStatus}
                      className="px-2 py-0.5 rounded bg-low/30 hover:bg-low/50 text-[10px] text-low transition-colors"
                    >
                      Resolved
                    </button>
                  </div>
                </div>
              </div>

              {/* Formatted Incident Report */}
              <div className="pt-4 border-t border-white/10 space-y-3">
                {/* MD5 & SHA-256 Hash Output from Colab notebook */}
                {scanResult.incident_report.md5_hash && (
                  <div className="p-3 rounded bg-cyber-900 border border-white/5 space-y-1 font-mono text-[11px]">
                    <div className="text-accent font-bold">--- Cryptographic Hashes (hashlib) ---</div>
                    <div>File: <span className="text-foreground">{scanResult.incident_report.target_name}</span></div>
                    <div className="text-muted-foreground">MD5 Hash    : <span className="text-accent">{scanResult.incident_report.md5_hash}</span></div>
                    <div className="text-muted-foreground">SHA-256 Hash: <span className="text-accent">{scanResult.incident_report.sha256_hash}</span></div>
                  </div>
                )}

                {/* Risk Score & Indicators from Colab notebook */}
                {scanResult.incident_report.risk_score !== undefined && (
                  <div className="p-3 rounded bg-cyber-900 border border-white/5 space-y-1 font-mono text-[11px]">
                    <div className="text-accent font-bold">--- Static Inspection & Risk Score ---</div>
                    {scanResult.incident_report.detected_indicators?.map((ind) => (
                      <div key={ind} className="text-medium">
                        ⚠️ Suspicious indicator found: {ind}
                      </div>
                    ))}
                    <div className="text-foreground font-bold pt-1">
                      Risk Score: {scanResult.incident_report.risk_score}/100
                    </div>
                  </div>
                )}

                <div className="text-accent font-bold">--- Incident Report ---</div>
                <div className="grid grid-cols-[140px_1fr] gap-x-4 gap-y-1 text-muted-foreground text-xs font-mono">
                  <span>Timestamp</span>
                  <span className="text-foreground">: {scanResult.incident_report.timestamp}</span>
                  <span>File / Target</span>
                  <span className="text-foreground">: {scanResult.incident_report.target_name}</span>
                  <span>Classification</span>
                  <span className="text-critical font-bold">: {scanResult.incident_report.classification}</span>
                  <span>Confidence</span>
                  <span className="text-foreground">: {scanResult.incident_report.confidence}</span>
                  <span>Action Taken</span>
                  <span className="text-foreground">: {scanResult.incident_report.action_taken}</span>
                  <span>Status</span>
                  <span className="text-accent font-bold">: {analystStatus}</span>
                </div>
                <div className="text-muted-foreground text-xs pt-1">------------------------</div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
