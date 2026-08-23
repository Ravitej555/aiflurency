"use client";

/**
 * ThreatLens AI — ThreatCard Component
 * Animated card for a single threat event with severity indicator,
 * status badge, CVE reference, and quick-action buttons
 */

import { useState } from "react";
import { motion } from "framer-motion";
import {
  AlertTriangle,
  Clock,
  Server,
  Network,
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  Loader2,
  Bot,
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { threats as threatsApi } from "@/lib/api";
import type { ThreatEvent, ThreatSeverity, ThreatStatus } from "@/types";

/** Format a UTC ISO date string to IST (India Standard Time, UTC+5:30) */
function toIST(utcDateStr: string): string {
  return new Date(utcDateStr).toLocaleString("en-IN", {
    timeZone: "Asia/Kolkata",
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  }) + " IST";
}

// ── Severity Config ───────────────────────────────────────────────────────────
const SEVERITY_CONFIG: Record<
  ThreatSeverity,
  { badge: string; border: string; dot: string; label: string }
> = {
  critical: {
    badge:  "badge-critical",
    border: "border-l-critical",
    dot:    "bg-critical animate-threat-pulse shadow-critical-glow",
    label:  "CRITICAL",
  },
  high: {
    badge:  "badge-high",
    border: "border-l-high",
    dot:    "bg-high animate-threat-pulse",
    label:  "HIGH",
  },
  medium: {
    badge:  "badge-medium",
    border: "border-l-medium",
    dot:    "bg-medium",
    label:  "MEDIUM",
  },
  low: {
    badge:  "badge-low",
    border: "border-l-low",
    dot:    "bg-low",
    label:  "LOW",
  },
  info: {
    badge:  "badge-info",
    border: "border-l-info",
    dot:    "bg-info",
    label:  "INFO",
  },
};

const STATUS_LABELS: Record<ThreatStatus, string> = {
  open:           "Open",
  investigating:  "Investigating",
  contained:      "Contained",
  resolved:       "Resolved",
  false_positive: "False Positive",
};

// ── Props ─────────────────────────────────────────────────────────────────────
interface ThreatCardProps {
  threat: ThreatEvent;
  onUpdate?: (updated: ThreatEvent) => void;
}

// ── Component ─────────────────────────────────────────────────────────────────
export function ThreatCard({ threat, onUpdate }: ThreatCardProps) {
  const [expanded, setExpanded] = useState(false);
  const [resolving, setResolving] = useState(false);

  const config = SEVERITY_CONFIG[threat.severity] ?? SEVERITY_CONFIG.info;
  const timeAgo = formatDistanceToNow(new Date(threat.detected_at), { addSuffix: true });
  const istTimestamp = toIST(threat.detected_at);

  const handleResolve = async () => {
    if (threat.is_resolved) return;
    setResolving(true);
    try {
      const updated = await threatsApi.update(threat.id, { is_resolved: true });
      onUpdate?.(updated);
    } catch (e) {
      console.error(e);
    } finally {
      setResolving(false);
    }
  };

  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 20 }}
      transition={{ duration: 0.3 }}
      className={`glass-card border-l-2 ${config.border} overflow-hidden`}
    >
      {/* Main Row */}
      <div className="p-4">
        <div className="flex items-start gap-3">
          {/* Severity dot */}
          <div className="mt-1.5 shrink-0">
            <div className={`w-2.5 h-2.5 rounded-full ${config.dot}`} />
          </div>

          {/* Content */}
          <div className="flex-1 min-w-0 space-y-1.5">
            <div className="flex items-start justify-between gap-2">
              <h3 className="text-sm font-semibold leading-tight line-clamp-2 pr-2">
                {threat.title}
              </h3>
              <div className="flex items-center gap-1.5 shrink-0">
                <span className={config.badge}>{config.label}</span>
                {threat.is_resolved && (
                  <span className="badge-severity bg-low/10 text-low border border-low/30">
                    ✓ Resolved
                  </span>
                )}
              </div>
            </div>

            {/* Meta row */}
            <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
              <span
                  className="flex items-center gap-1 cursor-default"
                  title={istTimestamp}
                >
                <Clock className="w-3 h-3" /> {timeAgo}
              </span>
              {threat.affected_asset && (
                <span className="flex items-center gap-1">
                  <Server className="w-3 h-3" /> {threat.affected_asset}
                </span>
              )}
              {threat.source_ip && (
                <span className="flex items-center gap-1 font-mono">
                  <Network className="w-3 h-3" /> {threat.source_ip}
                </span>
              )}
              {threat.cve_id && (
                <span className="font-mono text-accent/80 bg-accent/5 px-1.5 py-0.5 rounded text-xs">
                  {threat.cve_id}
                </span>
              )}
              <span className="px-1.5 py-0.5 rounded bg-white/5 text-xs">
                {STATUS_LABELS[threat.status]}
              </span>
            </div>
          </div>
        </div>

        {/* Action Row */}
        <div className="flex items-center justify-between mt-3 pt-3 border-t border-white/5">
          <button
            onClick={() => setExpanded(!expanded)}
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            {expanded ? "Less" : "Details"}
          </button>

          <div className="flex items-center gap-2">
            {/* CVSS Score */}
            {threat.cvss_score !== null && (
              <span className="text-xs font-mono text-muted-foreground">
                CVSS {threat.cvss_score.toFixed(1)}
              </span>
            )}

            {/* Resolve button */}
            {!threat.is_resolved && (
              <button
                onClick={handleResolve}
                disabled={resolving}
                className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-md bg-low/10 text-low border border-low/20
                           hover:bg-low/20 transition-colors disabled:opacity-50"
              >
                {resolving ? (
                  <Loader2 className="w-3 h-3 animate-spin" />
                ) : (
                  <CheckCircle2 className="w-3 h-3" />
                )}
                Resolve
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Expanded Details */}
      <motion.div
        initial={false}
        animate={{ height: expanded ? "auto" : 0 }}
        transition={{ duration: 0.25 }}
        className="overflow-hidden"
      >
        <div className="px-4 pb-4 pt-0 space-y-3 border-t border-white/5">
          {/* Description */}
          {threat.description && (
            <p className="text-xs text-muted-foreground leading-relaxed">
              {threat.description}
            </p>
          )}

          {/* AI Recommendation */}
          {threat.ai_recommendation && (
            <div className="p-3 rounded-lg bg-accent/5 border border-accent/15">
              <div className="flex items-center gap-1.5 mb-1.5 text-xs font-medium text-accent">
                <Bot className="w-3.5 h-3.5" />
                AI Recommendation
                {threat.ai_confidence !== null && (
                  <span className="ml-auto text-muted-foreground">
                    {Math.round(threat.ai_confidence * 100)}% confidence
                  </span>
                )}
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed">
                {threat.ai_recommendation}
              </p>
            </div>
          )}

          {/* IPs Grid */}
          <div className="grid grid-cols-2 gap-2 text-xs">
            {threat.source_ip && (
              <div className="p-2 rounded bg-white/3 border border-white/5">
                <div className="text-muted-foreground mb-0.5">Source IP</div>
                <div className="font-mono text-foreground">{threat.source_ip}</div>
              </div>
            )}
            {threat.destination_ip && (
              <div className="p-2 rounded bg-white/3 border border-white/5">
                <div className="text-muted-foreground mb-0.5">Destination IP</div>
                <div className="font-mono text-foreground">{threat.destination_ip}</div>
              </div>
            )}
            {threat.threat_type && (
              <div className="p-2 rounded bg-white/3 border border-white/5">
                <div className="text-muted-foreground mb-0.5">Threat Type</div>
                <div className="capitalize">{threat.threat_type.replace(/_/g, " ")}</div>
              </div>
            )}
            {threat.affected_asset && (
              <div className="p-2 rounded bg-white/3 border border-white/5">
                <div className="text-muted-foreground mb-0.5">Affected Asset</div>
                <div className="font-mono">{threat.affected_asset}</div>
              </div>
            )}
            {/* Detected At — IST */}
            <div className="p-2 rounded bg-white/3 border border-white/5 col-span-2">
              <div className="text-muted-foreground mb-0.5 flex items-center gap-1">
                <Clock className="w-3 h-3" /> Detected At (IST)
              </div>
              <div className="font-mono text-foreground">{istTimestamp}</div>
            </div>
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
}
