"use client";

/**
 * ThreatLens AI — Trend Analysis Component
 *
 * Renders classification detection counts breakdown, pandas-style dataset view,
 * and visual trend distribution.
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { TrendingUp, BarChart2, PieChart, ShieldAlert } from "lucide-react";
import { threats as threatsApi } from "@/lib/api";
import type { ThreatStats } from "@/types";

export function TrendAnalysis() {
  const [stats, setStats] = useState<ThreatStats | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchStats = () => {
    setLoading(true);
    threatsApi
      .stats()
      .then(setStats)
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const classificationCounts = stats?.classification_counts || {
    Worm: 1,
    Ransomware: 0,
    Phishing: 0,
    Trojan: 0,
  };

  const totalDetections = Object.values(classificationCounts).reduce((a, b) => a + b, 0);

  return (
    <div className="space-y-6">
      <div className="glass-card p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-bold flex items-center gap-2">
              <TrendingUp className="w-5 h-5 text-accent" />
              Threat Trend & Classification Analysis
            </h2>
            <p className="text-xs text-muted-foreground mt-1">
              Aggregated threat metrics, detection frequency by malware classification, and historical trend reporting.
            </p>
          </div>
          <button
            onClick={fetchStats}
            className="text-xs px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
          >
            Refresh Metrics
          </button>
        </div>

        {/* Pandas-style Output Block (Exact User Requested Format) */}
        <div className="p-4 rounded-xl bg-cyber-950/90 border border-accent/20 font-mono text-xs text-foreground space-y-2 shadow-cyber">
          <div className="text-accent font-bold">--- Trend Analysis ---</div>
          <div className="text-muted-foreground pt-2 font-semibold">Detection Counts:</div>
          <div className="text-muted-foreground pl-2 font-semibold"> classification</div>

          <div className="space-y-1 pl-2 font-mono">
            {Object.entries(classificationCounts).map(([cls, count]) => (
              <div key={cls} className="flex items-center gap-8">
                <span className="w-24 text-foreground font-bold">{cls}</span>
                <span className="text-accent font-semibold">{count}</span>
              </div>
            ))}
          </div>
          <div className="text-muted-foreground text-[11px] pt-1">
            Name: count, dtype: int64
          </div>
        </div>

        {/* Visual Progress Breakdown */}
        <div className="space-y-4 pt-2">
          <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <BarChart2 className="w-4 h-4 text-accent" /> Classification Distribution
          </h3>

          <div className="space-y-3">
            {Object.entries(classificationCounts).map(([cls, count]) => {
              const percentage = totalDetections > 0 ? Math.round((count / totalDetections) * 100) : 0;
              return (
                <div key={cls} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-medium text-foreground">{cls}</span>
                    <span className="text-muted-foreground font-mono">
                      {count} ({percentage}%)
                    </span>
                  </div>
                  <div className="w-full h-2.5 rounded-full bg-cyber-900 overflow-hidden border border-white/5">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${percentage}%` }}
                      transition={{ duration: 0.6, ease: "easeOut" }}
                      className="h-full bg-gradient-to-r from-accent to-blue-500 rounded-full"
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
