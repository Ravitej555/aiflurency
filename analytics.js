/**
 * ThreatLens AI — Privacy-Preserving Web Analytics & SOC Telemetry Engine
 * ───────────────────────────────────────────────────────────────────────
 * Zero-cookie, GDPR/CCPA compliant client-side visitor telemetry.
 * Tracks page impressions, session duration, referrers, and device profiles
 * while integrating seamlessly with the ThreatLens SOC Status Bar.
 */

(function () {
  'use strict';

  const STORAGE_KEY_SESSIONS = 'threatlens_analytics_sessions';
  const STORAGE_KEY_TOTAL_PV = 'threatlens_analytics_total_pv';
  const STORAGE_KEY_LAST_VISIT = 'threatlens_analytics_last_visit';

  // 1. Session & Identity (strictly local, zero cookies)
  let sessionId = sessionStorage.getItem('threatlens_session_id');
  if (!sessionId) {
    sessionId = 'sess_' + Math.random().toString(36).substring(2, 9) + Date.now().toString(36);
    sessionStorage.setItem('threatlens_session_id', sessionId);
  }

  // Visit count tracking
  let totalPageviews = parseInt(localStorage.getItem(STORAGE_KEY_TOTAL_PV) || '0', 10) + 1;
  localStorage.setItem(STORAGE_KEY_TOTAL_PV, totalPageviews.toString());
  localStorage.setItem(STORAGE_KEY_LAST_VISIT, new Date().toISOString());

  // Device & Viewport categorization
  const width = window.innerWidth;
  const deviceType = width < 768 ? 'Mobile' : width < 1024 ? 'Tablet' : 'Desktop';
  const screenRes = `${window.screen.width}x${window.screen.height}`;
  const referrer = document.referrer ? new URL(document.referrer).hostname : 'Direct / Organic';
  const pagePath = window.location.pathname + window.location.hash;

  // Session timer
  const sessionStartTime = Date.now();
  function getDurationSec() {
    return Math.floor((Date.now() - sessionStartTime) / 1000);
  }

  // 2. Telemetry payload
  const visitorTelemetry = {
    sessionId,
    deviceType,
    screenRes,
    viewport: `${window.innerWidth}x${window.innerHeight}`,
    referrer,
    pagePath,
    pageTitle: document.title,
    userAgent: navigator.userAgent,
    language: navigator.language || 'en-US',
    totalVisitsRecorded: totalPageviews,
    timestamp: new Date().toISOString(),
    events: []
  };

  // 3. UI Update: ThreatLens SOC Status Strip Integration
  function updateSocStatusStrip() {
    // If there's an analytics item in the status strip, update it
    const strip = document.querySelector('.status-strip');
    if (strip) {
      let analyticsItem = document.getElementById('ss-analytics-counter');
      if (!analyticsItem) {
        analyticsItem = document.createElement('div');
        analyticsItem.id = 'ss-analytics-counter';
        analyticsItem.className = 'ss-item';
        analyticsItem.innerHTML = `
          <i class="fa-solid fa-chart-line" style="color:var(--cyan);font-size:.65rem"></i>
          <span>ANALYTICS:</span>
          <span class="ss-val" id="ss-analytics-val" style="color:var(--cyan)">${totalPageviews} PVs (${deviceType})</span>
        `;
        // Insert before the right-aligned clock
        const rightClock = strip.querySelector('.ss-right');
        if (rightClock) {
          strip.insertBefore(analyticsItem, rightClock);
        } else {
          strip.appendChild(analyticsItem);
        }
      } else {
        const valSpan = document.getElementById('ss-analytics-val');
        if (valSpan) valSpan.textContent = `${totalPageviews} PVs (${deviceType})`;
      }
    }
  }

  // 4. Custom Event Tracker API
  window.ThreatLensAnalytics = {
    getTelemetry: () => ({ ...visitorTelemetry, durationSeconds: getDurationSec() }),
    trackEvent: (eventName, metadata = {}) => {
      const ev = {
        event: eventName,
        time: new Date().toISOString(),
        durationSeconds: getDurationSec(),
        metadata
      };
      visitorTelemetry.events.push(ev);
      console.log(`[ThreatLens Analytics] Event: ${eventName}`, ev);
      
      // Dispatch custom DOM event
      window.dispatchEvent(new CustomEvent('threatlens:telemetry', { detail: ev }));
    }
  };

  // Run on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      updateSocStatusStrip();
      window.ThreatLensAnalytics.trackEvent('page_view', { path: pagePath, title: document.title });
    });
  } else {
    updateSocStatusStrip();
    window.ThreatLensAnalytics.trackEvent('page_view', { path: pagePath, title: document.title });
  }

  // Periodic heartbeat every 30 seconds
  setInterval(() => {
    window.ThreatLensAnalytics.trackEvent('heartbeat', { duration: getDurationSec() });
  }, 30000);

})();
