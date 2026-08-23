"use client";

/**
 * ThreatLens AI — Main Dashboard Page
 *
 * Features:
 * - Animated stat cards (total, open, critical, resolved threats)
 * - Severity breakdown bar chart (Recharts)
 * - Live threat feed with filtering
 * - Framer Motion entrance animations
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
  Shield,
  AlertTriangle,
  CheckCircle2,
  Activity,
  TrendingUp,
  Zap,
} from "lucide-react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from "recharts";
import { threats as threatsApi } from "@/lib/api";
import { ThreatFeed } from "@/components/ThreatFeed";
import type { ThreatStats } from "@/types";

// ── Animation Variants ────────────────────────────────────────────────────────
const containerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.1 } },
};

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.4, ease: "easeOut" } },
};

// ── Stat Card Component ───────────────────────────────────────────────────────
interface StatCardProps {
  label: string;
  value: number | string;
  icon: React.ReactNode;
  color: string;
  trend?: string;
  pulse?: boolean;
}

function StatCard({ label, value, icon, color, trend, pulse }: StatCardProps) {
  return (
    <motion.div variants={itemVariants} className="stat-card group relative overflow-hidden">
      {/* Background glow */}
      <div className={`absolute inset-0 ${color} opacity-0 group-hover:opacity-100 transition-opacity duration-300 rounded-xl`} />

      <div className="relative z-10 flex items-start justify-between">
        <div>
          <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider mb-1">
            {label}
          </p>
          <p className={`text-3xl font-bold ${pulse ? "animate-threat-pulse" : ""}`}>
            {typeof value === "number" ? value.toLocaleString() : value}
          </p>
          {trend && (
            <p className="text-xs text-muted-foreground mt-1 flex items-center gap-1">
              <TrendingUp className="w-3 h-3" /> {trend}
            </p>
          )}
        </div>
        <div className={`p-2.5 rounded-lg bg-white/5 border border-white/10`}>
          {icon}
        </div>
      </div>
    </motion.div>
  );
}

// ── Chart Colors ──────────────────────────────────────────────────────────────
const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ff2d55",
  high:     "#ff6b35",
  medium:   "#ffd60a",
  low:      "#30d158",
  info:     "#636366",
};

// ── Page ──────────────────────────────────────────────────────────────────────
import { ScannerTab } from "@/components/ScannerTab";
import { TrendAnalysis } from "@/components/TrendAnalysis";

export default function DashboardPage() {
  const [stats, setStats] = useState<ThreatStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeView, setActiveView] = useState<"overview" | "scanner" | "trends">("overview");

  const loadStats = () => {
    setLoading(true);
    threatsApi
      .stats()
      .then(setStats)
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadStats();
  }, []);

  const chartData = stats
    ? Object.entries(stats.severity_breakdown).map(([severity, count]) => ({
        severity: severity.charAt(0).toUpperCase() + severity.slice(1),
        count,
        fill: SEVERITY_COLORS[severity] || "#636366",
      }))
    : [];

  return (
    <div className="space-y-6">
      {/* ── Header & Main Mode Toggle ────────────────────────────────────── */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="flex flex-col sm:flex-row sm:items-center justify-between gap-4"
      >
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <span className="text-accent">⬡</span>
            ThreatLens AI Operations Center
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Real-time threat detection, AI malware scanning, incident reporting & trend analysis
          </p>
        </div>

        {/* Mode Selector Tabs */}
        <div className="flex items-center gap-1 p-1 bg-cyber-900 glass-card border border-white/10 text-xs">
          <button
            onClick={() => setActiveView("overview")}
            className={`px-3 py-1.5 rounded-lg font-semibold transition-all ${
              activeView === "overview"
                ? "bg-accent text-cyber-950 shadow-cyber"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            🛡️ Live Feed
          </button>
          <button
            onClick={() => setActiveView("scanner")}
            className={`px-3 py-1.5 rounded-lg font-semibold transition-all ${
              activeView === "scanner"
                ? "bg-accent text-cyber-950 shadow-cyber"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            🔍 File & Link Scanner
          </button>
          <button
            onClick={() => setActiveView("trends")}
            className={`px-3 py-1.5 rounded-lg font-semibold transition-all ${
              activeView === "trends"
                ? "bg-accent text-cyber-950 shadow-cyber"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            📊 Trend Analysis
          </button>
        </div>
      </motion.div>

      {/* ── Stat Cards Bar ─────────────────────────────────────────────────── */}
      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        className="grid grid-cols-2 lg:grid-cols-4 gap-4"
      >
        <StatCard
          label="Total Threats"
          value={loading ? "—" : (stats?.total ?? 0)}
          icon={<Shield className="w-5 h-5 text-accent" />}
          color="bg-accent/5"
        />
        <StatCard
          label="Open"
          value={loading ? "—" : (stats?.open ?? 0)}
          icon={<Activity className="w-5 h-5 text-high" />}
          color="bg-high/5"
          pulse={!!stats?.open}
        />
        <StatCard
          label="Critical"
          value={loading ? "—" : (stats?.critical ?? 0)}
          icon={<AlertTriangle className="w-5 h-5 text-critical" />}
          color="bg-critical/5"
          pulse={!!stats?.critical}
        />
        <StatCard
          label="Resolved"
          value={loading ? "—" : (stats?.resolved ?? 0)}
          icon={<CheckCircle2 className="w-5 h-5 text-low" />}
          color="bg-low/5"
        />
      </motion.div>

      {/* ── Dynamic Tab View ──────────────────────────────────────────────── */}
      {activeView === "overview" && (
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="grid grid-cols-1 lg:grid-cols-3 gap-6"
        >
          {/* Severity Distribution Chart */}
          <motion.div variants={itemVariants} className="glass-card p-5 lg:col-span-1">
            <div className="flex items-center gap-2 mb-4">
              <Zap className="w-4 h-4 text-accent" />
              <h2 className="font-semibold text-sm">Severity Distribution</h2>
            </div>
            {chartData.length > 0 ? (
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={chartData} margin={{ top: 5, right: 0, left: -20, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                  <XAxis
                    dataKey="severity"
                    tick={{ fill: "#636366", fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <YAxis tick={{ fill: "#636366", fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip
                    contentStyle={{
                      background: "#0d1526",
                      border: "1px solid rgba(255,255,255,0.1)",
                      borderRadius: "8px",
                      fontSize: "12px",
                    }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {chartData.map((entry, i) => (
                      <rect key={i} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-48 flex items-center justify-center text-muted-foreground text-sm">
                No threat data yet
              </div>
            )}
          </motion.div>

          {/* Threat Feed */}
          <motion.div variants={itemVariants} className="lg:col-span-2">
            <ThreatFeed />
          </motion.div>
        </motion.div>
      )}

      {activeView === "scanner" && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
          <ScannerTab onScanComplete={loadStats} />
        </motion.div>
      )}

      {activeView === "trends" && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
          <TrendAnalysis />
        </motion.div>
      )}
    </div>
  );
}
