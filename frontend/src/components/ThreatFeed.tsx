"use client";

/**
 * ThreatLens AI — ThreatFeed Component
 * Live, paginated, filterable list of threat events with auto-refresh
 */

import { useCallback, useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { RefreshCw, Filter, Search, AlertTriangle, Loader2 } from "lucide-react";
import { threats as threatsApi } from "@/lib/api";
import { ThreatCard } from "./ThreatCard";
import type { ThreatEvent, ThreatSeverity, ThreatListResponse } from "@/types";

const SEVERITY_OPTIONS: { label: string; value: ThreatSeverity | "" }[] = [
  { label: "All Severities", value: "" },
  { label: "Critical",       value: "critical" },
  { label: "High",           value: "high" },
  { label: "Medium",         value: "medium" },
  { label: "Low",            value: "low" },
  { label: "Info",           value: "info" },
];

export function ThreatFeed() {
  const [data, setData] = useState<ThreatListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [severity, setSeverity] = useState<ThreatSeverity | "">("");
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [page, setPage] = useState(1);

  // Debounce search input
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(search), 400);
    return () => clearTimeout(timer);
  }, [search]);

  const fetchThreats = useCallback(
    async (showRefreshSpinner = false) => {
      if (showRefreshSpinner) setRefreshing(true);
      else setLoading(true);

      try {
        const result = await threatsApi.list({
          page,
          size: 10,
          severity: severity || undefined,
          search: debouncedSearch || undefined,
        });
        setData(result);
      } catch (e) {
        console.error("Failed to fetch threats", e);
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [page, severity, debouncedSearch]
  );

  // Auto-refresh every 30 seconds
  useEffect(() => {
    fetchThreats();
    const interval = setInterval(() => fetchThreats(true), 30_000);
    return () => clearInterval(interval);
  }, [fetchThreats]);

  // Reset to page 1 when filters change
  useEffect(() => { setPage(1); }, [severity, debouncedSearch]);

  const handleUpdate = (updated: ThreatEvent) => {
    setData((prev) =>
      prev
        ? { ...prev, items: prev.items.map((t) => (t.id === updated.id ? updated : t)) }
        : prev
    );
  };

  return (
    <div className="glass-card p-5 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-accent" />
          <h2 className="font-semibold text-sm">Live Threat Feed</h2>
          {data && (
            <span className="text-xs text-muted-foreground bg-white/5 px-1.5 py-0.5 rounded">
              {data.total} total
            </span>
          )}
        </div>
        <button
          onClick={() => fetchThreats(true)}
          disabled={refreshing}
          className="p-1.5 rounded-lg text-muted-foreground hover:text-accent hover:bg-accent/5 transition-colors"
          aria-label="Refresh threats"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? "animate-spin" : ""}`} />
        </button>
      </div>

      {/* Filters */}
      <div className="flex gap-2">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground pointer-events-none" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search threats…"
            className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-cyber-700/50 border border-white/10 text-xs
                       placeholder:text-muted-foreground/50
                       focus:outline-none focus:ring-1 focus:ring-accent/40 focus:border-accent/40 transition-colors"
          />
        </div>

        {/* Severity filter */}
        <div className="relative">
          <Filter className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground pointer-events-none" />
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value as ThreatSeverity | "")}
            className="pl-6 pr-3 py-1.5 rounded-lg bg-cyber-700/50 border border-white/10 text-xs
                       focus:outline-none focus:ring-1 focus:ring-accent/40 transition-colors appearance-none cursor-pointer"
          >
            {SEVERITY_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Feed Content */}
      {loading ? (
        <div className="flex items-center justify-center h-48">
          <Loader2 className="w-6 h-6 animate-spin text-accent" />
        </div>
      ) : !data?.items.length ? (
        <div className="flex flex-col items-center justify-center h-48 text-muted-foreground gap-2">
          <AlertTriangle className="w-8 h-8 opacity-30" />
          <p className="text-sm">No threats found</p>
          {(search || severity) && (
            <button
              onClick={() => { setSearch(""); setSeverity(""); }}
              className="text-xs text-accent hover:underline"
            >
              Clear filters
            </button>
          )}
        </div>
      ) : (
        <div className="space-y-3 max-h-[500px] overflow-y-auto pr-1">
          <AnimatePresence mode="popLayout">
            {data.items.map((threat) => (
              <ThreatCard key={threat.id} threat={threat} onUpdate={handleUpdate} />
            ))}
          </AnimatePresence>
        </div>
      )}

      {/* Pagination */}
      {data && data.pages > 1 && (
        <div className="flex items-center justify-between pt-2 border-t border-white/5">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            className="text-xs px-3 py-1.5 rounded-lg bg-white/5 border border-white/10
                       hover:bg-white/10 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            ← Previous
          </button>
          <span className="text-xs text-muted-foreground">
            Page {data.page} of {data.pages}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(data.pages, p + 1))}
            disabled={page === data.pages}
            className="text-xs px-3 py-1.5 rounded-lg bg-white/5 border border-white/10
                       hover:bg-white/10 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            Next →
          </button>
        </div>
      )}
    </div>
  );
}
