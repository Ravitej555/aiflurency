"use client";

/**
 * ThreatLens AI — Login Page
 * Glassmorphism card with animated entrance, form validation, and JWT auth flow
 */

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { Shield, Eye, EyeOff, AlertCircle, Loader2 } from "lucide-react";
import { auth } from "@/lib/api";
import type { Metadata } from "next";

export default function LoginPage() {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    startTransition(async () => {
      try {
        await auth.login({ username, password });
        router.push("/");
        router.refresh();
      } catch (err: unknown) {
        const axiosErr = err as { response?: { data?: { detail?: string }; status?: number } };
        if (axiosErr.response?.status === 401) {
          setError("Invalid username or password. Please try again.");
        } else if (axiosErr.response?.status === 403) {
          setError("Your account has been disabled. Contact your administrator.");
        } else {
          setError("Unable to connect to the server. Please try again.");
        }
      }
    });
  };

  return (
    <div className="min-h-[calc(100vh-8rem)] flex items-center justify-center px-4">
      {/* Background effects */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-accent/3 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 w-80 h-80 bg-blue-500/3 rounded-full blur-3xl" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 30, scale: 0.97 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.5, ease: "easeOut" }}
        className="w-full max-w-md relative z-10"
      >
        {/* Header */}
        <div className="text-center mb-8">
          <motion.div
            initial={{ scale: 0, rotate: -180 }}
            animate={{ scale: 1, rotate: 0 }}
            transition={{ duration: 0.6, delay: 0.1, type: "spring" }}
            className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-accent/10 border border-accent/30 mb-4 shadow-cyber"
          >
            <Shield className="w-8 h-8 text-accent" />
          </motion.div>
          <h1 className="text-2xl font-bold">ThreatLens AI</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Security Operations Portal
          </p>
        </div>

        {/* Login Card */}
        <div className="glass-card p-8 space-y-6">
          <div>
            <h2 className="text-lg font-semibold">Sign In</h2>
            <p className="text-sm text-muted-foreground">
              Access your security dashboard
            </p>
          </div>

          {/* Error Alert */}
          {error && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              className="flex items-start gap-3 p-3 rounded-lg bg-critical/10 border border-critical/30 text-critical text-sm"
            >
              <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
              <span>{error}</span>
            </motion.div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Username */}
            <div className="space-y-1.5">
              <label htmlFor="username" className="text-sm font-medium">
                Username or Email
              </label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="analyst or analyst@threatlens.ai"
                required
                autoComplete="username"
                className="w-full px-3 py-2.5 rounded-lg bg-cyber-700/50 border border-white/10 text-sm
                           placeholder:text-muted-foreground/50
                           focus:outline-none focus:ring-1 focus:ring-accent/50 focus:border-accent/50
                           transition-colors"
              />
            </div>

            {/* Password */}
            <div className="space-y-1.5">
              <label htmlFor="password" className="text-sm font-medium">
                Password
              </label>
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  required
                  autoComplete="current-password"
                  className="w-full px-3 py-2.5 pr-10 rounded-lg bg-cyber-700/50 border border-white/10 text-sm
                             placeholder:text-muted-foreground/50
                             focus:outline-none focus:ring-1 focus:ring-accent/50 focus:border-accent/50
                             transition-colors"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Submit */}
            <button
              type="submit"
              disabled={isPending || !username || !password}
              className="w-full py-2.5 rounded-lg font-medium text-sm transition-all duration-200
                         bg-accent text-cyber-950 hover:bg-accent-hover
                         disabled:opacity-50 disabled:cursor-not-allowed
                         focus:outline-none focus:ring-2 focus:ring-accent/50 focus:ring-offset-2 focus:ring-offset-cyber-950
                         flex items-center justify-center gap-2 shadow-cyber"
            >
              {isPending ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Authenticating…
                </>
              ) : (
                "Access Secure Portal"
              )}
            </button>
          </form>

          {/* Demo credentials notice */}
          <div className="pt-2 border-t border-white/5 text-center">
            <p className="text-xs text-muted-foreground">
              🔒 All connections are encrypted end-to-end
            </p>
          </div>
        </div>
      </motion.div>
    </div>
  );
}
