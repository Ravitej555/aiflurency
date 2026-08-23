import type { Config } from "tailwindcss";
import animate from "tailwindcss-animate";

const config: Config = {
  darkMode: ["class"],
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      // ── Design Tokens ───────────────────────────────────────────────────
      colors: {
        // Cyber dark palette
        cyber: {
          950: "#020817",
          900: "#0a0f1e",
          800: "#0d1526",
          700: "#111d35",
          600: "#162040",
        },
        // ThreatLens accent — electric cyan
        accent: {
          DEFAULT: "#00d4ff",
          hover:   "#00b8e6",
          muted:   "#00d4ff33",
        },
        // Threat severity
        critical: { DEFAULT: "#ff2d55", muted: "#ff2d5520" },
        high:     { DEFAULT: "#ff6b35", muted: "#ff6b3520" },
        medium:   { DEFAULT: "#ffd60a", muted: "#ffd60a20" },
        low:      { DEFAULT: "#30d158", muted: "#30d15820" },
        info:     { DEFAULT: "#636366", muted: "#63636620" },
        // shadcn/ui semantic tokens
        border: "hsl(var(--border))",
        input:  "hsl(var(--input))",
        ring:   "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground:  "hsl(var(--foreground))",
        primary: {
          DEFAULT:    "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT:    "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        muted: {
          DEFAULT:    "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        card: {
          DEFAULT:    "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
      },

      // ── Typography ─────────────────────────────────────────────────────
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      },

      // ── Gradients ──────────────────────────────────────────────────────
      backgroundImage: {
        "cyber-gradient":   "linear-gradient(135deg, #020817 0%, #0d1526 50%, #020817 100%)",
        "accent-gradient":  "linear-gradient(135deg, #00d4ff 0%, #0080ff 100%)",
        "critical-gradient":"linear-gradient(135deg, #ff2d55 0%, #ff0044 100%)",
        "glow-accent":      "radial-gradient(ellipse at center, #00d4ff20 0%, transparent 70%)",
      },

      // ── Border Radius (shadcn compatible) ─────────────────────────────
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },

      // ── Box Shadows ───────────────────────────────────────────────────
      boxShadow: {
        "cyber":          "0 0 20px rgba(0, 212, 255, 0.15)",
        "cyber-lg":       "0 0 40px rgba(0, 212, 255, 0.2)",
        "critical-glow":  "0 0 20px rgba(255, 45, 85, 0.3)",
        "card":           "0 4px 6px -1px rgba(0,0,0,0.4), 0 2px 4px -2px rgba(0,0,0,0.4)",
      },

      // ── Animations ────────────────────────────────────────────────────
      keyframes: {
        "accordion-down": {
          from: { height: "0" },
          to:   { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to:   { height: "0" },
        },
        "pulse-glow": {
          "0%, 100%": { boxShadow: "0 0 10px rgba(0,212,255,0.3)" },
          "50%":      { boxShadow: "0 0 25px rgba(0,212,255,0.6)" },
        },
        "scan-line": {
          "0%":   { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100vh)" },
        },
        "threat-pulse": {
          "0%, 100%": { opacity: "1" },
          "50%":      { opacity: "0.5" },
        },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up":   "accordion-up 0.2s ease-out",
        "pulse-glow":     "pulse-glow 2s ease-in-out infinite",
        "scan-line":      "scan-line 3s linear infinite",
        "threat-pulse":   "threat-pulse 1.5s ease-in-out infinite",
      },
    },
  },
  plugins: [animate],
};

export default config;
