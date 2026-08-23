// Minimal shadcn/ui-compatible Toaster component
"use client";

export function Toaster() {
  // Full shadcn/ui toast implementation can be added via: npx shadcn-ui@latest add toast
  // This placeholder ensures the layout compiles without the full shadcn installation
  return <div id="toaster-root" aria-live="polite" aria-atomic="true" />;
}
