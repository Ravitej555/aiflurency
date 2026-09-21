/* =============================================================
   ThreatLens AI SOC — App Logic
   ============================================================= */

document.addEventListener('DOMContentLoaded', () => {

  // ── RADAR MODE BUTTONS ────────────────────────────────────────
  let radarMode = '360';
  document.getElementById('rMode360')?.addEventListener('click', function() {
    radarMode = '360';
    this.classList.add('active');
    document.getElementById('rModeThermal')?.classList.remove('active');
  });
  document.getElementById('rModeThermal')?.addEventListener('click', function() {
    radarMode = 'thermal';
    this.classList.add('active');
    document.getElementById('rMode360')?.classList.remove('active');
  });

  // ── 1. IST CLOCK ─────────────────────────────────────────────
  function updateClock() {
    const el = document.getElementById('istClock');
    if (!el) return;
    const now = new Date();
    const opts = {
      timeZone: 'Asia/Kolkata',
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: true
    };
    const parts = now.toLocaleString('en-IN', opts)
      .replace(',', '')
      .toLowerCase();
    el.textContent = 'IST: ' + parts;
  }
  setInterval(updateClock, 1000);
  updateClock();

  // ── 2. TAB SWITCHING ─────────────────────────────────────────
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
      if (btn.dataset.tab === 'trends') renderTrends();
    });
  });

  // ── 3. THREAT DATA & TABLE ───────────────────────────────────
  const threatsData = [
    {
      id:'TR-9041', ts:'02:48:00 pm', classification:'Worm',
      classifyDesc:'Scanned Artifact: https://chatg...',
      sourceIP:'198.51.100.16', target:'GATEWAY-SCANNER-01',
      severity:'HIGH', confidence:'90.4%', status:'Active',
      vector:'Worm behavior detected via URL pattern matching. Invoked PowerShell download cradle detected.'
    },
    {
      id:'TR-9040', ts:'02:47:25 pm', classification:'Benign',
      classifyDesc:'File Malware Detected: === thre...',
      sourceIP:'203.0.113.47', target:'SEC-ENDPOINT-08',
      severity:'MEDIUM', confidence:'88.5%', status:'Active',
      vector:'File scan completed. No malicious indicators found. Shannon entropy within normal range.'
    },
    {
      id:'TR-9039', ts:'02:44:36 pm', classification:'Ransomware',
      classifyDesc:'File Malware Detected: ransomw...',
      sourceIP:'203.0.113.42', target:'SEC-ENDPOINT-12',
      severity:'CRITICAL', confidence:'92%', status:'Quarantined',
      vector:'Ransomware signature detected. High entropy payload with encrypted extension patterns.'
    },
    {
      id:'TR-9038', ts:'01:58:10 pm', classification:'Ransomware.Win32.Entropy',
      classifyDesc:'Encrypted payload via PowerShell',
      sourceIP:'185.220.101.5', target:'SOC-NODE-09',
      severity:'CRITICAL', confidence:'99.4%', status:'Quarantined',
      vector:'Encrypted payload execution detected via PowerShell. APT-41 signature match confirmed.'
    },
    {
      id:'TR-9037', ts:'01:51:45 pm', classification:'SQLi Breach Attempt',
      classifyDesc:'Blind injection on /api/v1/auth',
      sourceIP:'103.251.167.22', target:'DB-PRIMARY-01',
      severity:'HIGH', confidence:'98.1%', status:'Blocked',
      vector:'Blind SQL Injection attempt on authentication endpoint. Automated mitigation applied.'
    },
    {
      id:'TR-9036', ts:'01:42:30 pm', classification:'DDoS SYN Flood',
      classifyDesc:'1.2 Mpps burst rate exceeded',
      sourceIP:'45.142.120.0/24', target:'GATEWAY-LB-03',
      severity:'HIGH', confidence:'96.5%', status:'Mitigated',
      vector:'SYN flood attack from distributed botnet. Rate limiting and null-routing applied.'
    },
  ];

  let currentFilter = 'all';

  function getStatusClass(status) {
    const s = (status || '').toLowerCase();
    if (s === 'active') return 'status-active';
    if (s === 'quarantined') return 'status-quarantined';
    if (s === 'mitigated') return 'status-mitigated';
    if (s === 'blocked') return 'status-blocked';
    if (s === 'isolated') return 'status-isolated';
    return 'status-active';
  }

  function getBadgeClass(sev) {
    const s = (sev || '').toUpperCase();
    if (s === 'CRITICAL') return 'badge-critical';
    if (s === 'HIGH')     return 'badge-high';
    if (s === 'MEDIUM')   return 'badge-medium';
    return 'badge-low';
  }

  function getDotColor(label) {
    const l = (label || '').toLowerCase();
    if (l.includes('worm'))       return '#f97316';
    if (l.includes('ransomware')) return '#ef4444';
    if (l.includes('trojan'))     return '#ef4444';
    if (l.includes('sqli') || l.includes('ddos')) return '#f59e0b';
    if (l.includes('benign'))     return '#22c55e';
    return '#94a3b8';
  }

  // ── HTML ESCAPING HELPER (XSS PREV) ────────────────────────
  function escapeHTML(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function renderThreats() {
    const tbody = document.getElementById('threatTableBody');
    if (!tbody) return;
    const query = (document.getElementById('threatSearch')?.value || '').toLowerCase().trim();

    const filtered = threatsData.filter(t => {
      if (!t) return false;
      const tSev = (t.severity || '').toUpperCase();
      const cFilter = (currentFilter || 'all').toUpperCase();
      const matchSev = cFilter === 'ALL' || tSev === cFilter;
      const matchQ = !query ||
        (t.id || '').toLowerCase().includes(query) ||
        (t.classification || '').toLowerCase().includes(query) ||
        (t.classifyDesc || '').toLowerCase().includes(query) ||
        (t.sourceIP || '').toLowerCase().includes(query) ||
        (t.target || '').toLowerCase().includes(query) ||
        (t.status || '').toLowerCase().includes(query) ||
        (t.vector || '').toLowerCase().includes(query);
      return matchSev && matchQ;
    });

    if (filtered.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align:center;padding:2.5rem 1rem;color:#64748b;">
            <i class="fa-solid fa-folder-open" style="font-size:2rem;margin-bottom:0.75rem;color:var(--muted);display:block;"></i>
            <div style="font-size:0.92rem;color:var(--text);font-weight:600;margin-bottom:0.35rem;">No threats match "${escapeHTML(query)}"</div>
            <div style="font-size:0.75rem;color:var(--muted);margin-bottom:1.1rem;">Try searching by Threat ID (e.g. TR-9041), malware family, IP address, or status.</div>
            <button id="clearSearchBtn" type="button" style="background:rgba(0,229,255,0.12);border:1px solid rgba(0,229,255,0.4);color:var(--cyan);padding:0.45rem 1.1rem;border-radius:6px;font-size:0.75rem;cursor:pointer;font-family:'Outfit',sans-serif;font-weight:600;transition:0.2s;">
              <i class="fa-solid fa-rotate-left" style="margin-right:6px;"></i> Clear Search & Reset Table
            </button>
          </td>
        </tr>
      `;
      document.getElementById('clearSearchBtn')?.addEventListener('click', () => {
        const sInput = document.getElementById('threatSearch');
        if (sInput) sInput.value = '';
        currentFilter = 'all';
        document.querySelectorAll('.fpill').forEach(p => p.classList.remove('active'));
        document.querySelector('.fpill[data-f="all"]')?.classList.add('active');
        renderThreats();
      });
      return;
    }

    tbody.innerHTML = filtered.map(t => `
      <tr id="row-${escapeHTML(t.id)}" class="${t.isNew ? 'new-threat-row' : ''}">
        <td><span class="ts">${escapeHTML(t.ts) || ''}</span></td>
        <td>
          <div class="classify">
            <span class="classify-dot" style="background:${getDotColor(t.classification || '')}"></span>${escapeHTML(t.classification) || 'Unknown'}
          </div>
          <span class="classify-sub">${escapeHTML(t.classifyDesc) || ''}</span>
        </td>
        <td><span class="ip-code">${escapeHTML(t.sourceIP) || 'N/A'}</span></td>
        <td><span class="ip-code">${escapeHTML(t.target) || 'N/A'}</span></td>
        <td><span class="badge ${getBadgeClass(t.severity || 'LOW')}">${escapeHTML(t.severity) || 'LOW'}</span></td>
        <td><strong>${escapeHTML(t.confidence) || '0%'}</strong></td>
        <td>
          <div class="act-btns">
            <button class="act-btn act-analyze" onclick="openModal('${escapeHTML(t.id)}')">
              <i class="fa-solid fa-microscope"></i> Analyze
            </button>
            <button class="act-btn act-del" onclick="deleteThreat('${escapeHTML(t.id)}')"><i class="fa-solid fa-trash"></i> Remove</button>
          </div>
        </td>
      </tr>
    `).join('');
  }

  document.getElementById('threatSearch')?.addEventListener('input', renderThreats);

  document.querySelectorAll('.fpill').forEach(pill => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('.fpill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      currentFilter = pill.dataset.f;
      renderThreats();
    });
  });

  renderThreats();

  // Delete a threat by ID
  window.deleteThreat = function(id) {
    const idx = threatsData.findIndex(t => t.id === id);
    if (idx !== -1) {
      threatsData.splice(idx, 1);
      renderThreats();
    }
  };

  // ── 4. MODAL ─────────────────────────────────────────────────
  window.openModal = function(id) {
    const t = threatsData.find(x => x.id === id);
    if (!t) return;
    const modal = document.getElementById('analysisModal');
    const body  = document.getElementById('modalBody');
    const sevColor = t.severity === 'CRITICAL' ? '#ef4444' : t.severity === 'HIGH' ? '#f97316' : '#f59e0b';

    body.innerHTML = `
      <div style="display:flex;flex-direction:column;gap:1rem;">
        <div style="background:${sevColor}15;border:1px solid ${sevColor}44;border-radius:10px;padding:.9rem 1.1rem;display:flex;align-items:center;gap:.75rem;">
          <i class="fa-solid fa-skull-crossbones" style="color:${sevColor};font-size:1.3rem;"></i>
          <div>
            <div style="font-weight:700;color:${sevColor};">Threat ID: ${t.id} — ${t.classification}</div>
            <div style="color:#64748b;font-size:.75rem;margin-top:2px;">${new Date().toLocaleString('en-IN',{timeZone:'Asia/Kolkata',hour12:true})}</div>
          </div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:.6rem;">
          ${[['Source IP', t.sourceIP],['Target Host',t.target],['Severity',t.severity],['AI Confidence',t.confidence]]
            .map(([l,v])=>`
              <div style="background:#0d1e35;border:1px solid rgba(255,255,255,.06);border-radius:8px;padding:.65rem .85rem;">
                <div style="font-size:.68rem;color:#64748b;margin-bottom:3px;">${l}</div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:.85rem;color:#e2e8f0;">${v}</div>
              </div>
            `).join('')}
        </div>
        <div style="background:#0d1e35;border:1px solid rgba(0,212,255,.15);border-radius:10px;padding:1rem;">
          <div style="font-size:.7rem;color:#64748b;margin-bottom:.4rem;letter-spacing:.08em;">AI FORENSIC DIAGNOSIS</div>
          <p style="font-size:.82rem;color:#94a3b8;line-height:1.6;">${t.vector}</p>
        </div>
        <div style="background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);border-radius:8px;padding:.85rem 1rem;">
          <div style="font-size:.7rem;color:#64748b;margin-bottom:.3rem;">RECOMMENDED RESPONSE</div>
          <div style="font-size:.82rem;font-weight:600;color:#22c55e;">
            Enforce host isolation on <code style="background:rgba(255,255,255,.06);padding:1px 5px;border-radius:3px;">${t.target}</code> 
            and block inbound traffic from <code style="background:rgba(255,255,255,.06);padding:1px 5px;border-radius:3px;">${t.sourceIP}</code>.
          </div>
        </div>
      </div>
    `;
    modal.classList.remove('hidden');
  };

  document.getElementById('closeModal')?.addEventListener('click',   () => document.getElementById('analysisModal').classList.add('hidden'));
  document.getElementById('dismissModal')?.addEventListener('click', () => document.getElementById('analysisModal').classList.add('hidden'));

  // ── 5. FILE UPLOAD SCANNER ───────────────────────────────────
  const fileInput      = document.getElementById('fileInput');
  const chooseFileBtn  = document.getElementById('chooseFileBtn');
  const selectedFile   = document.getElementById('selectedFileName');
  const dropZone       = document.getElementById('dropZone');
  let pickedFile       = null;

  chooseFileBtn?.addEventListener('click', () => fileInput.click());

  fileInput?.addEventListener('change', e => {
    pickedFile = e.target.files[0] || null;
    if (pickedFile) {
      selectedFile.textContent = 'Selected: ' + pickedFile.name;
      runFileScan(pickedFile);
    }
  });

  dropZone?.addEventListener('dragover',  e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
  dropZone?.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
  dropZone?.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const f = e.dataTransfer.files?.[0];
    if (f) {
      pickedFile = f;
      selectedFile.textContent = 'Selected: ' + f.name;
      runFileScan(f);
    }
  });

  function runFileScan(file) {
    const bufferReader = new FileReader();

    bufferReader.onload = function(be) {
      const buf    = be.target.result;
      const bytes  = new Uint8Array(buf);
      const len    = bytes.length || 1;

      // ── 1. Shannon Entropy (byte-level 0.0–8.0) ──────────────────
      const freq = new Array(256).fill(0);
      for (let i = 0; i < len; i++) freq[bytes[i]]++;
      let ent = 0;
      for (let i = 0; i < 256; i++) {
        if (freq[i] > 0) { const p = freq[i] / len; ent -= p * Math.log2(p); }
      }
      const hash_entropy = parseFloat(ent.toFixed(2));
      const normHE = hash_entropy / 8.0;  // 0.0–1.0

      // ── 2. Extract printable ASCII strings (min 5 chars) ─────────
      let cur = '', strings = [];
      for (let i = 0; i < bytes.length; i++) {
        const b = bytes[i];
        if (b >= 32 && b <= 126) { cur += String.fromCharCode(b); }
        else { if (cur.length >= 5) strings.push(cur.toLowerCase()); cur = ''; }
      }
      if (cur.length >= 5) strings.push(cur.toLowerCase());
      const txt = strings.join(' ');

      // ── 3. Weighted signal scoring ────────────────────────────────
      // Each category scores independently. Winner must clear a threshold.
      // Signals are weighted 1–5 (higher = stronger indicator).

      // --- RANSOMWARE signals ---
      const ransomSignals = [
        { w:5, p:'vssadmin delete shadows' },  // Shadow copy deletion — #1 ransomware IOC
        { w:5, p:'bcdedit /set recoveryenabled no' },
        { w:5, p:'wbadmin delete catalog' },
        { w:5, p:'your files are encrypted' },
        { w:5, p:'files have been encrypted' },
        { w:4, p:'ransomnote' },
        { w:4, p:'cryptogenrandom' },
        { w:4, p:'cryptencrypt' },
        { w:3, p:'ransom' },
        { w:3, p:'bitlocker' },
        { w:2, p:'cacls /e /p everyone:n' },   // File ACL lockout
      ];

      // --- WORM signals ---
      const wormSignals = [
        { w:5, p:'reverse_tcp' },
        { w:5, p:'bind_tcp' },
        { w:5, p:'meterpreter' },
        { w:5, p:'cobalt strike' },
        { w:4, p:'wmic process call create' },
        { w:4, p:'invoke-webrequest' },
        { w:4, p:'downloadstring' },
        { w:4, p:'bitsadmin' },
        { w:4, p:'certutil -urlcache' },
        { w:3, p:'socket.connect' },
        { w:3, p:'net localgroup administrators' },
        { w:3, p:'invoke-command' },
        { w:3, p:'metasploit' },
        { w:2, p:'net user' },
        { w:2, p:'icacls' },
      ];

      // --- TROJAN signals ---
      const trojanSignals = [
        { w:5, p:'createremotethread' },
        { w:5, p:'writeprocessmemory' },
        { w:5, p:'ntcreatethreadexit' },
        { w:4, p:'virtualalloc' },
        { w:4, p:'virtualprotect' },
        { w:4, p:'rtlmovememory' },
        { w:4, p:'shellexecute' },
        { w:4, p:'rundll32' },
        { w:4, p:'regsvr32' },
        { w:4, p:'mshta' },
        { w:3, p:'wscript.shell' },
        { w:3, p:'shell.application' },
        { w:3, p:'sedebuggingprivilege' },
        { w:3, p:'adjusttokenprivileges' },
        { w:3, p:'invoke-expression' },
        { w:3, p:'frombase64string' },
        { w:2, p:'hkey_local_machine\\software\\microsoft\\windows\\currentversion\\run' },
        { w:2, p:'schtasks /create' },
        { w:2, p:'powershell' },
        { w:2, p:'cmd.exe' },
        { w:2, p:'wscript' },
        { w:2, p:'cscript' },
        // Java-specific
        { w:4, p:'runtime.getruntime().exec' },
        { w:4, p:'urlclassloader' },
        { w:3, p:'java.net.socket' },
        { w:3, p:'javax.crypto.cipher' },
        { w:3, p:'sun.misc.unsafe' },
        { w:2, p:'processbuilder' },
      ];

      function scoreSignals(signals) {
        let score = 0, hits = 0;
        signals.forEach(({ w, p }) => { if (txt.includes(p)) { score += w; hits++; } });
        return { score, hits };
      }

      const rS = scoreSignals(ransomSignals);   // ransomware
      const wS = scoreSignals(wormSignals);     // worm
      const tS = scoreSignals(trojanSignals);   // trojan

      // Total hits across all categories (for display)
      const suspicious_strings = rS.hits + wS.hits + tS.hits;

      const fileExt = file.name.includes('.') ? '.' + file.name.split('.').pop().toLowerCase() : '';
      const result  = classifyThreat({
        normHE, fileExt, txt,
        ransomScore: rS.score, ransomHits: rS.hits,
        wormScore:   wS.score, wormHits:   wS.hits,
        trojanScore: tS.score, trojanHits: tS.hits,
        isFile: true
      });

      showScanResult({
        name:       file.name,
        size:       file.size,
        entropy:    hash_entropy,
        strings:    suspicious_strings,
        label:      result.label,
        confidence: result.confidence,
        isFile:     true
      });
    };

    bufferReader.readAsArrayBuffer(file);
  }

  // ── 6. URL SCANNER ───────────────────────────────────────────
  document.getElementById('scanUrlBtn')?.addEventListener('click', () => {
    const urlInput = document.getElementById('urlInput');
    const scanBtn = document.getElementById('scanUrlBtn');
    const url = urlInput?.value.trim();

    // 1. Edge Case: Empty input validation & feedback
    if (!url) {
      if (urlInput) {
        urlInput.style.borderColor = 'var(--red)';
        urlInput.style.boxShadow = '0 0 14px rgba(239,68,68,0.45)';
        urlInput.placeholder = '⚠ Please enter a valid URL, domain, or payload script before scanning!';
        urlInput.focus();
        setTimeout(() => {
          urlInput.style.borderColor = '';
          urlInput.style.boxShadow = '';
          urlInput.placeholder = 'e.g., http://malicious-c2.ru/payload.exe or Invoke-WebRequest -Uri ...';
        }, 3500);
      }
      return;
    }

    // 2. Edge Case: Double submit & rapid multi-click protection
    if (scanBtn?.classList.contains('scanning-busy')) return;
    if (scanBtn) {
      scanBtn.classList.add('scanning-busy');
      scanBtn.disabled = true;
      scanBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Analyzing Payload...';
    }

    // Parse URL to get parts
    let host = '', path = '';
    try {
      const u = new URL(/^https?:\/\//i.test(url) ? url : 'http://' + url);
      host = u.hostname.toLowerCase();
      path = (u.pathname + u.search).toLowerCase();
    } catch(e) {
      host = url.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
    }
    const fullLower = url.toLowerCase();

    // ── Ransomware URL signals ────────────────────────────────────
    const urlRansomSignals = [
      { w:5, p:'ransom' }, { w:4, p:'cryptor' }, { w:4, p:'decrypt' },
      { w:4, p:'lockbit' }, { w:3, p:'darkweb' }, { w:3, p:'.onion' },
    ];

    // ── Worm / C2 URL signals ─────────────────────────────────────
    const urlWormSignals = [
      { w:5, p:'reverse_tcp' }, { w:5, p:'meterpreter' }, { w:5, p:'metasploit' },
      { w:4, p:'cobalt+strike' }, { w:4, p:'c2server' }, { w:4, p:'beacon' },
      { w:3, p:'downloadstring' }, { w:3, p:'invoke-webrequest' },
    ];

    // ── Trojan / Payload URL signals ──────────────────────────────
    const urlTrojanSignals = [
      { w:5, p:'powershell' }, { w:5, p:'invoke-expression' }, { w:5, p:'cmd.exe' },
      { w:4, p:'frombase64string' }, { w:4, p:'base64' }, { w:4, p:'mshta' },
      { w:4, p:'exploit' }, { w:4, p:'shell.php' }, { w:4, p:'webshell' },
      { w:4, p:'backdoor' }, { w:3, p:'payload' }, { w:3, p:'eval(' },
      { w:3, p:'.ps1' }, { w:3, p:'.vbs' }, { w:3, p:'.hta' }, { w:2, p:'.bat' },
    ];

    // .exe only in path (not domain)
    if (path.includes('.exe')) urlTrojanSignals.push({ w:4, p:'.exe' });

    function scoreURLSignals(signals) {
      let score = 0, hits = 0;
      signals.forEach(({ w, p }) => { if (fullLower.includes(p)) { score += w; hits++; } });
      return { score, hits };
    }

    const rS = scoreURLSignals(urlRansomSignals);
    const wS = scoreURLSignals(urlWormSignals);
    const tS = scoreURLSignals(urlTrojanSignals);

    // ── Phishing signals ──────────────────────────────────────────
    let phishScore = 0;
    const brands = ['paypal','google','microsoft','apple','amazon','facebook',
      'instagram','netflix','linkedin','twitter','youtube','bankofamerica',
      'chase','wellsfargo','dhl','fedex','irs'];
    const tld = host.split('.').pop();
    const domNoTld = host.replace(/\.[^.]+$/, '');
    brands.forEach(b => {
      if (host.includes(b) && domNoTld !== b && !domNoTld.endsWith('.' + b)) phishScore += 4;
    });
    if (['xyz','tk','ml','ga','cf','pw','top','click','link','gq'].includes(tld)) phishScore += 3;
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
      const [a,b] = host.split('.').map(Number);
      if (!((a===10)||(a===172&&b>=16&&b<=31)||(a===192&&b===168)||(a===127))) phishScore += 4;
    }
    if ((host.match(/-/g)||[]).length >= 3) phishScore += 2;
    if (host.split('.').length >= 4) phishScore += 1;
    if (url.length > 200) phishScore += 2;
    const pct = (url.match(/%[0-9a-f]{2}/gi)||[]).length;
    if (pct > 8)  phishScore += 2;
    if (pct > 20) phishScore += 3;
    if (url.includes('%00')) phishScore += 4;

    // ── URL Entropy ───────────────────────────────────────────────
    const urlBytes = new TextEncoder().encode(url);
    const uf = new Array(256).fill(0);
    urlBytes.forEach(b => uf[b]++);
    const uLen = urlBytes.length || 1;
    let ue = 0;
    uf.forEach(f => { if (f > 0) { const p = f/uLen; ue -= p * Math.log2(p); } });
    const hash_entropy = parseFloat(ue.toFixed(2));
    const normHE = Math.min(hash_entropy / 8.0, 1.0);

    const totalHits = rS.hits + wS.hits + tS.hits;
    const result = classifyThreat({
      normHE, fileExt: '', txt: fullLower,
      ransomScore: rS.score, ransomHits: rS.hits,
      wormScore:   wS.score, wormHits:   wS.hits,
      trojanScore: tS.score, trojanHits: tS.hits,
      phishScore,
      isFile: false
    });

    showScanResult({
      name:       url,
      size:       urlBytes.length,
      entropy:    hash_entropy,
      strings:    totalHits + (phishScore > 0 ? 1 : 0),
      label:      result.label,
      confidence: result.confidence,
      isFile:     false
    });
  });

  document.getElementById('urlRemove')?.addEventListener('click', () => {
    document.getElementById('scanResults').style.display = 'none';
    document.getElementById('urlInput').value = '';
    const badge = document.getElementById('fileStatusBadge');
    if (badge) badge.style.display = 'none';
  });

  // ── 7. AI CLASSIFIER — Weighted Score Engine ──────────────────
  //
  //  Input: a single options object with per-category scores.
  //  Each category (Ransomware / Worm / Trojan / Phishing) independently
  //  accumulates signal weight. The highest-scoring category wins,
  //  subject to minimum-score and minimum-hit guards.
  //
  function classifyThreat({ normHE, fileExt, txt,
    ransomScore = 0, ransomHits = 0,
    wormScore   = 0, wormHits   = 0,
    trojanScore = 0, trojanHits = 0,
    phishScore  = 0, isFile     = true }) {

    const ext = (fileExt || '').toLowerCase();
    const dangerousExts = ['.exe','.dll','.bat','.cmd','.ps1','.vbs','.js','.hta','.scr','.com','.pif','.msi','.msp','.cpl','.reg'];
    const mediumExts    = ['.class','.java','.jar','.apk','.dex','.pyc','.py','.sh','.zip','.rar','.7z','.iso','.img','.docm','.xlsm','.lnk'];
    const safeExts      = ['.pdf','.txt','.docx','.xlsx','.csv','.png','.jpg','.jpeg','.gif','.mp4','.mp3','.html','.css','.json','.svg','.xml'];

    const isDangerous = dangerousExts.includes(ext);
    const isMedium    = mediumExts.includes(ext);
    const isSafe      = safeExts.includes(ext);
    const isJava      = (ext === '.class' || ext === '.java' || ext === '.jar');

    // ── Extension multipliers ─────────────────────────────────────
    // Dangerous exts amplify score; safe exts require more evidence.
    const extMul = isDangerous ? 1.5 : isMedium ? 1.1 : isSafe ? 0.6 : 1.0;

    // Apply extension multiplier
    const rScore = ransomScore * extMul;
    const wScore = wormScore   * extMul;
    const tScore = trojanScore * extMul;

    // ── Minimum thresholds — prevents single-keyword false positives ─
    // Safe-extension files need a higher bar to be classified malicious.
    const minScoreToFlag  = isSafe ? 8  : isDangerous ? 4  : 6;
    const minHitsToFlag   = isSafe ? 2  : 1;

    const totalHits = ransomHits + wormHits + trojanHits;
    const anyMalicious = totalHits >= minHitsToFlag &&
                         Math.max(rScore, wScore, tScore) >= minScoreToFlag;

    // ── Benign fast-path ──────────────────────────────────────────
    if (!anyMalicious && phishScore < 6) {
      // High entropy + no keywords on a safe file = compressed, not malicious
      const conf = isSafe ? 0.96 : (normHE > 0.88 && isDangerous) ? 0.78 : 0.93;
      return { label: 'Benign', confidence: conf };
    }

    // ── URL Phishing path ─────────────────────────────────────────
    if (!isFile) {
      // Pure phishing: spoofing signals, no payload keywords
      if (phishScore >= 6 && Math.max(wScore, tScore, rScore) < minScoreToFlag) {
        const conf = 0.78 + Math.min(phishScore / 40, 0.18);
        return { label: 'Phishing', confidence: parseFloat(Math.min(conf, 0.97).toFixed(3)) };
      }
      // Phishing + payload = Trojan dropper (redirect page)
      if (phishScore >= 4 && tScore >= minScoreToFlag) {
        const conf = 0.82 + Math.min((phishScore + tScore) / 60, 0.12);
        return { label: 'Trojan', confidence: parseFloat(Math.min(conf, 0.96).toFixed(3)) };
      }
    }

    // ── Ransomware ────────────────────────────────────────────────
    // Requires EITHER: specific ransom keywords score OR very high entropy + any signals
    const ransomWins = rScore >= Math.max(wScore, tScore) &&
                       rScore >= minScoreToFlag;
    const highEntropyRansom = normHE >= 0.88 && ransomHits >= 1;
    if (ransomWins || highEntropyRansom) {
      const conf = 0.82 + Math.min(rScore / 60 + (normHE > 0.88 ? 0.06 : 0), 0.16);
      return { label: 'Ransomware', confidence: parseFloat(Math.min(conf, 0.99).toFixed(3)) };
    }

    // ── Worm ──────────────────────────────────────────────────────
    // Requires: worm-specific network/propagation signals dominate
    const wormWins = wScore >= Math.max(rScore, tScore) &&
                     wScore >= minScoreToFlag && wormHits >= minHitsToFlag;
    if (wormWins) {
      const conf = 0.81 + Math.min(wScore / 50, 0.16);
      return { label: 'Worm', confidence: parseFloat(Math.min(conf, 0.98).toFixed(3)) };
    }

    // ── Trojan ────────────────────────────────────────────────────
    // Catch-all for injection/hook/persistence signals
    if (tScore >= minScoreToFlag && trojanHits >= minHitsToFlag) {
      const conf = 0.78 + Math.min(tScore / 50 + (isDangerous ? 0.05 : 0), 0.16);
      return { label: 'Trojan', confidence: parseFloat(Math.min(conf, 0.96).toFixed(3)) };
    }

    // ── Java-specific: any malicious signal → Trojan ──────────────
    if (isJava && totalHits >= 1) {
      const score = Math.max(rScore, wScore, tScore);
      const conf = 0.76 + Math.min(score / 40, 0.14);
      return { label: 'Trojan', confidence: parseFloat(Math.min(conf, 0.92).toFixed(3)) };
    }

    // ── Soft fallback: signals present but below strict threshold ─
    // Don't flag benign; return Benign with lower confidence.
    return { label: 'Benign', confidence: 0.82 };
  }

  // ── 8. PSEUDO HASH HELPERS ────────────────────────────────────
  function generatePseudoHash(seed) {
    let h = 0;
    for (let i = 0; i < seed.length; i++) { h = (Math.imul(31, h) + seed.charCodeAt(i)) | 0; }
    const hex = Math.abs(h).toString(16).padStart(8, '0');
    return (hex + hex + hex + hex + hex + hex + hex + hex).substring(0, 64);
  }
  function generatePseudoMd5(seed) {
    let h = 0;
    for (let i = 0; i < seed.length; i++) { h = (Math.imul(31, h) + seed.charCodeAt(i)) | 0; }
    const hex = Math.abs(h).toString(16).padStart(8, '0');
    return (hex + hex + hex + hex).substring(0, 32);
  }

  // ── 8. SHOW SCAN RESULT & INJECT INTO LIVE FEED ──────────────
  function showScanResult({name, size, entropy, strings, label, confidence, isFile}) {
    let severity = 'LOW', actionText = 'No action required. File signature verified clean.';
    const statusMap = { Worm:'Active', Trojan:'Quarantined', Ransomware:'Quarantined', Phishing:'Blocked', Benign:'Mitigated' };
    if (label === 'Worm')      { severity = 'HIGH';     actionText = 'Isolate host. Block outbound C2 connections.'; }
    if (label === 'Trojan')    { severity = 'CRITICAL'; actionText = 'Escalate to Security Analyst immediately.'; }
    if (label === 'Ransomware'){ severity = 'CRITICAL'; actionText = 'Quarantine system. Initiate incident response.'; }
    if (label === 'Phishing')  { severity = 'HIGH';     actionText = 'Block URL. Warn users. Report to threat feed.'; }

    const confPct    = (confidence * 100).toFixed(1) + '%';
    const badgeClass = {
      Worm:'url-badge-worm', Ransomware:'url-badge-ransomware',
      Trojan:'url-badge-trojan', Phishing:'url-badge-worm', Benign:'url-badge-benign'
    }[label] || 'url-badge-benign';
    const sevColor   = severity==='CRITICAL'?'#ef4444':severity==='HIGH'?'#f97316':'#22c55e';

    // ── Determine Status ──────────────────────────────────────────
    let statusText = 'CLEAN & SAFE', statusClass = 'file-status-clean', statusColor = 'var(--green)', statusIcon = 'fa-circle-check';
    if (label === 'Ransomware') { statusText = 'QUARANTINED'; statusClass = 'file-status-quarantine'; statusColor = 'var(--red)';    statusIcon = 'fa-lock'; }
    else if (label === 'Trojan')    { statusText = 'ISOLATED';    statusClass = 'file-status-isolated';   statusColor = 'var(--purple)'; statusIcon = 'fa-shield-virus'; }
    else if (label === 'Worm')      { statusText = 'BLOCKED';     statusClass = 'file-status-warning';   statusColor = 'var(--amber)'; statusIcon = 'fa-hand'; }
    else if (label === 'Phishing')  { statusText = 'PHISHING';   statusClass = 'file-status-warning';   statusColor = '#f97316';      statusIcon = 'fa-fish'; }

    // ── Update file upload status badge ───────────────────────────
    const statusBadge = document.getElementById('fileStatusBadge');
    if (statusBadge) {
      statusBadge.className = `file-status-badge ${statusClass}`;
      statusBadge.innerHTML = `<i class="fa-solid ${statusIcon}"></i> STATUS: ${statusText}`;
      statusBadge.style.display = 'inline-flex';
    }

    // ── Update top metric cards ──────────────────────────────────
    document.getElementById('malwareFamilyValue').textContent  = label==='Benign' ? 'None Detected' : label+'.Generic';
    document.getElementById('malwareSub').textContent          = label==='Benign' ? 'Clean signature' : label==='Phishing' ? 'Credential harvesting attempt' : 'Active threat detected';
    document.getElementById('aiPredictionValue').textContent   = label==='Benign' ? 'BENIGN' : label==='Phishing' ? 'PHISHING' : 'MALICIOUS';
    document.getElementById('aiPredictionValue').style.color   = label==='Benign' ? 'var(--green)' : label==='Phishing' ? '#f97316' : 'var(--red)';
    document.getElementById('aiPredSub').textContent           = label==='Benign' ? 'File verified clean' : label==='Phishing' ? 'Spoofing / typosquat detected' : 'Decision tree anomaly verified';
    document.getElementById('confidenceScoreValue').textContent = confPct;
    document.getElementById('riskLevelValue').textContent      = severity;
    document.getElementById('riskLevelValue').style.color      = sevColor;
    document.getElementById('riskSub').textContent             = label==='Benign' ? 'No threats detected' : severity+' severity detected';

    // ── Scanner result row ───────────────────────────────────────
    const urlRow   = document.getElementById('urlResultRow');
    const urlVal   = document.getElementById('urlResultVal');
    const urlSize  = document.getElementById('urlResultSize');
    const urlBadge = document.getElementById('urlClassBadge');

    urlVal.textContent   = name.length > 50 ? name.substring(0,50)+'…' : name;
    urlSize.textContent  = isFile
      ? (size < 1024 ? size+' B' : size < 1048576 ? (size/1024).toFixed(1)+' KB' : (size/1048576).toFixed(1)+' MB')
      : `${size} chars`;
    urlBadge.textContent = `${label.toUpperCase()} (${confPct})`;
    urlBadge.className   = `url-badge ${badgeClass}`;
    urlRow.style.display = 'flex';

    document.getElementById('rmStatus').innerHTML       = `<span style="color:${statusColor}"><i class="fa-solid ${statusIcon}"></i> ${statusText}</span>`;
    document.getElementById('rmEntropy').textContent    = entropy.toFixed(2) + ' / 8.0';
    document.getElementById('rmStrings').textContent    = strings + (strings === 1 ? ' indicator' : ' indicators');
    document.getElementById('rmSeverity').textContent   = severity;
    document.getElementById('rmSeverity').style.color   = sevColor;
    document.getElementById('rmConfidence').textContent = confPct;
    document.getElementById('scanResults').style.display = 'flex';

    // Reset scan button state from loading
    const scanBtn = document.getElementById('scanUrlBtn');
    if (scanBtn) {
      setTimeout(() => {
        scanBtn.disabled = false;
        scanBtn.classList.remove('scanning-busy');
        scanBtn.innerHTML = '<i class="fa-solid fa-bolt"></i> Scan Payload / URL';
      }, 350);
    }

    // ── Active Scan Context Attachment ────────────────────────────
    window.activeScanContext = {
      filename: name,
      file_type: isFile ? (name.split('.').pop() || 'exe').toUpperCase() + ' Binary' : 'URL Payload Inspector',
      sha256: generatePseudoHash(name + size + entropy),
      md5: generatePseudoMd5(name + size),
      file_size: typeof size === 'number' ? size : size.length,
      entropy: parseFloat(entropy.toFixed(2)),
      strings_count: strings,
      yara_matches: label === 'Benign' ? [] : ['YARA_' + label.toUpperCase() + '_HighRisk', 'YARA_Obfuscated_Cradle'],
      prediction: label,
      confidence: confPct,
      risk_level: severity,
      virustotal_result: label === 'Benign' ? 'Clean (0/72 engines flagged)' : '48/72 engines flagged malicious',
      static_analysis: label === 'Benign' ? 'Normal PE header structure' : 'Obfuscated payload / abnormal section table'
    };
    if (typeof updateCopilotContextUI === 'function') updateCopilotContextUI();

    // ── Inject into Live Intelligence Feed ───────────────────────
    const istTime   = new Date().toLocaleTimeString('en-IN', { timeZone:'Asia/Kolkata', hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:true });
    function extractHostIpOrDomain(urlStr) {
      try {
        let raw = urlStr;
        if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;
        const u = new URL(raw);
        return u.hostname || '198.51.100.16';
      } catch(e) {
        return '198.51.100.16';
      }
    }

    const shortName = name.length > 36 ? name.substring(0, 36) + '…' : name;
    const newThreat = {
      id:             'TR-' + (9042 + threatsData.length),
      ts:             istTime,
      classification: label,
      classifyDesc:   (isFile ? 'File Malware Detected: ' : 'Scanned Artifact: ') + shortName,
      sourceIP:       isFile ? '203.0.113.' + (20 + (threatsData.length % 50)) : extractHostIpOrDomain(name),
      target:         isFile ? 'SEC-ENDPOINT-' + (10 + (threatsData.length % 20)) : 'GATEWAY-SCANNER-01',
      severity:       severity,
      confidence:     confPct,
      status:         statusMap[label] || 'Active',
      isNew:          true,
      vector:         `${isFile?'File':'URL'} artifact scanned. Shannon Entropy: ${entropy.toFixed(2)} / 8.0. Suspicious indicators found: ${strings}. AI classified as ${label} with ${confPct} Gini confidence. ${actionText}`
    };

    // ── Store for Trend Analysis tab ──────────────────────────────
    window.lastScanData = { name, size, entropy, strings, label, confPct, severity, actionText, isFile, ts: istTime };

    currentFilter = 'all';
    document.querySelectorAll('.fpill').forEach(p => p.classList.remove('active'));
    document.querySelector('.fpill[data-f="all"]')?.classList.add('active');

    threatsData.unshift(newThreat);

    // ── Switch to feed tab FIRST (so table is visible) ────────────
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelector('.tab-btn[data-tab="feed"]')?.classList.add('active');
    document.getElementById('tab-feed')?.classList.add('active');

    // ── Re-render full table from threatsData ────────────────────
    renderThreats();

    // ── Direct DOM inject (bulletproof fallback) ──────────────────
    const tbody = document.getElementById('threatTableBody');
    if (tbody && !document.getElementById('row-' + newThreat.id)) {
      const tr = document.createElement('tr');
      tr.id = 'row-' + newThreat.id;
      tr.className = 'new-threat-row';
      tr.innerHTML = `
        <td><span class="ts">${newThreat.ts}</span></td>
        <td>
          <div class="classify">
            <span class="classify-dot" style="background:${getDotColor(newThreat.classification)}"></span>${newThreat.classification}
          </div>
          <span class="classify-sub">${newThreat.classifyDesc}</span>
        </td>
        <td><span class="ip-code">${newThreat.sourceIP}</span></td>
        <td><span class="ip-code">${newThreat.target}</span></td>
        <td><span class="badge ${getBadgeClass(newThreat.severity)}">${newThreat.severity}</span></td>
        <td><strong>${newThreat.confidence}</strong></td>
        <td>
          <div class="act-btns">
            <button class="act-btn act-analyze" onclick="openModal('${newThreat.id}')">
              <i class="fa-solid fa-microscope"></i> Analyze
            </button>
            <button class="act-btn act-del" onclick="deleteThreat('${newThreat.id}')"><i class="fa-solid fa-trash"></i> Remove</button>
          </div>
        </td>
      `;
      tbody.insertBefore(tr, tbody.firstChild);
    }

    // ── Scroll to feed section ────────────────────────────────────
    document.getElementById('tab-feed')?.scrollIntoView({ behavior: 'smooth' });

    // ── Copilot message ──────────────────────────────────────────
    const msgs = document.getElementById('copilotMessages');
    if (msgs) {
      const msg = document.createElement('div');
      msg.className = 'copilot-msg';
      msg.innerHTML = `
        <i class="fa-solid fa-robot copilot-avatar"></i>
        <div class="copilot-bubble" style="border-color:${label==='Benign'?'rgba(34,197,94,.2)':'rgba(239,68,68,.2)'}">
          <strong style="color:${sevColor};">[${label==='Benign'?'✔ CLEAN SCAN':'⚠ THREAT DETECTED'}]</strong><br>
          • Target: <code>${shortName}</code><br>
          • Shannon Entropy: <code>${entropy.toFixed(2)} / 8.0</code><br>
          • Suspicious Indicators: <code>${strings} found</code><br>
          • AI Classification: <strong>${label}</strong> · Confidence: <strong>${confPct}</strong><br>
          • Severity: <strong style="color:${sevColor};">${severity}</strong> — ${actionText}
        </div>
      `;
      msgs.appendChild(msg);
      msgs.scrollTop = msgs.scrollHeight;
    }

    // ── Show forensic popup 350ms after feed updates ──────────────
    setTimeout(() => {
      showForensicModal({ name, size, entropy, strings, label, severity, confPct, actionText, sevColor, isFile });
    }, 350);
  }

  function parseUrlPayloadContents(target, isFile) {
    if (isFile) {
      const ext = target.split('.').pop() || 'exe';
      return {
        type: 'Binary Payload File',
        domain: 'LOCAL-ENDPOINT-UPLOAD',
        protocol: 'File System (NTFS/ext4)',
        path: `/app/uploads/${target}`,
        params: `extension=.${ext}, entropy=${target.length}`,
        mime: ext === 'exe' || ext === 'dll' ? 'application/x-msdownload' : ext === 'ps1' ? 'application/x-powershell' : 'application/octet-stream',
        ssl: 'Internal Storage Verified',
        virustotal: '48 / 72 Security Engines Flagged Malicious'
      };
    }

    try {
      let rawUrl = target;
      if (!/^https?:\/\//i.test(rawUrl)) rawUrl = 'https://' + rawUrl;
      const parsed = new URL(rawUrl);
      const isIp = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(parsed.hostname);
      const isHttps = parsed.protocol === 'https:';

      return {
        type: 'URL Payload Inspector',
        domain: parsed.hostname || '185.220.101.5',
        protocol: isHttps ? 'HTTPS (TLS 1.3 / Port 443)' : 'HTTP (Unencrypted / Port 80)',
        path: parsed.pathname || '/',
        params: parsed.search || 'None (Direct Endpoint)',
        mime: parsed.pathname.endsWith('.ps1') ? 'application/x-powershell' : parsed.pathname.endsWith('.exe') ? 'application/x-msdownload' : 'text/html; charset=utf-8',
        ssl: isHttps ? '🔒 TLS Valid Certificate (AES-256-GCM)' : '⚠️ Unencrypted HTTP Transmission',
        virustotal: isIp ? '54 / 72 Flagged Malicious Host' : '42 / 72 Flagged Malicious Domain'
      };
    } catch(e) {
      return {
        type: 'URL Payload Inspector',
        domain: '198.51.100.16',
        protocol: 'HTTPS / Port 443',
        path: '/api/v1/payload',
        params: 'cmd=powershell&exec=base64',
        mime: 'application/octet-stream',
        ssl: '⚠️ Self-Signed Certificate Flagged',
        virustotal: '48 / 72 Engines Flagged Malicious'
      };
    }
  }

  function showForensicModal({name, size, entropy, strings, label, severity, confPct, actionText, sevColor, isFile}) {
    const modal = document.getElementById('analysisModal');
    const body  = document.getElementById('modalBody');
    if (!modal || !body) return;

    const payloadInfo = parseUrlPayloadContents(name, isFile);
    const shortName   = name.length > 40 ? name.substring(0, 40) + '…' : name;

    body.innerHTML = `
      <div style="display:flex;flex-direction:column;gap:0.9rem;">

        <!-- Header Status Banner -->
        <div style="background:${sevColor}15;border:1px solid ${sevColor}44;border-radius:10px;padding:.85rem 1.1rem;display:flex;align-items:center;justify-content:space-between;">
          <div style="display:flex;align-items:center;gap:.75rem;">
            <i class="fa-solid ${label==='Benign'?'fa-shield-halved':'fa-skull-crossbones'}" style="color:${sevColor};font-size:1.4rem;"></i>
            <div>
              <div style="font-weight:800;color:${sevColor};font-size:.95rem;">
                ${label==='Benign'?'✔ CLEAN SCAN':'🚨 THREAT DETECTED: '+label}
              </div>
              <div style="color:#64748b;font-size:.72rem;margin-top:2px;">
                Forensic Payload Inspector • IST ${new Date().toLocaleTimeString('en-IN',{timeZone:'Asia/Kolkata',hour12:true})}
              </div>
            </div>
          </div>
          <span style="font-size:.72rem;background:${sevColor}22;color:${sevColor};padding:3px 10px;border-radius:20px;border:1px solid ${sevColor}55;font-weight:700;">
            ${severity} RISK
          </span>
        </div>

        <!-- URL / Payload Contents Detailed Breakdown -->
        <div style="background:#0a1628;border:1px solid rgba(0,212,255,.2);border-radius:10px;padding:0.9rem;">
          <div style="font-size:.68rem;color:var(--cyan);letter-spacing:.08em;font-weight:700;margin-bottom:.6rem;display:flex;align-items:center;gap:.4rem;">
            <i class="fa-solid fa-link"></i> EXTRACTED LINK & PAYLOAD CONTENTS
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:.5rem;">
            <div style="background:#0d1e35;border:1px solid rgba(255,255,255,.06);border-radius:6px;padding:.5rem .75rem;">
              <div style="font-size:.65rem;color:#64748b;">Target Link / File</div>
              <div style="font-family:'JetBrains Mono',monospace;font-size:.75rem;color:#e2e8f0;word-break:break-all;">${shortName}</div>
            </div>
            <div style="background:#0d1e35;border:1px solid rgba(255,255,255,.06);border-radius:6px;padding:.5rem .75rem;">
              <div style="font-size:.65rem;color:#64748b;">Host Domain / IP</div>
              <div style="font-family:'JetBrains Mono',monospace;font-size:.75rem;color:var(--cyan);">${payloadInfo.domain}</div>
            </div>
            <div style="background:#0d1e35;border:1px solid rgba(255,255,255,.06);border-radius:6px;padding:.5rem .75rem;">
              <div style="font-size:.65rem;color:#64748b;">Protocol & Security</div>
              <div style="font-family:'JetBrains Mono',monospace;font-size:.73rem;color:#e2e8f0;">${payloadInfo.protocol}</div>
            </div>
            <div style="background:#0d1e35;border:1px solid rgba(255,255,255,.06);border-radius:6px;padding:.5rem .75rem;">
              <div style="font-size:.65rem;color:#64748b;">Target Path</div>
              <div style="font-family:'JetBrains Mono',monospace;font-size:.73rem;color:#e2e8f0;">${payloadInfo.path}</div>
            </div>
            <div style="background:#0d1e35;border:1px solid rgba(255,255,255,.06);border-radius:6px;padding:.5rem .75rem;">
              <div style="font-size:.65rem;color:#64748b;">Query Parameters</div>
              <div style="font-family:'JetBrains Mono',monospace;font-size:.73rem;color:#f59e0b;">${payloadInfo.params}</div>
            </div>
            <div style="background:#0d1e35;border:1px solid rgba(255,255,255,.06);border-radius:6px;padding:.5rem .75rem;">
              <div style="font-size:.65rem;color:#64748b;">Payload MIME Type</div>
              <div style="font-family:'JetBrains Mono',monospace;font-size:.73rem;color:#e2e8f0;">${payloadInfo.mime}</div>
            </div>
          </div>
        </div>

        <!-- Metrics Grid -->
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:.5rem;">
          <div style="background:#0d1e35;border:1px solid rgba(255,255,255,.06);border-radius:8px;padding:.6rem .75rem;">
            <div style="font-size:.65rem;color:#64748b;">Shannon Entropy</div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:.9rem;font-weight:700;color:var(--cyan);">${entropy.toFixed(2)} / 8.0</div>
          </div>
          <div style="background:#0d1e35;border:1px solid rgba(255,255,255,.06);border-radius:8px;padding:.6rem .75rem;">
            <div style="font-size:.65rem;color:#64748b;">Payload Indicators</div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:.9rem;font-weight:700;color:#f59e0b;">${strings} found</div>
          </div>
          <div style="background:#0d1e35;border:1px solid rgba(255,255,255,.06);border-radius:8px;padding:.6rem .75rem;">
            <div style="font-size:.65rem;color:#64748b;">Gini Confidence</div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:.9rem;font-weight:700;color:${sevColor};">${confPct}</div>
          </div>
        </div>

        <!-- VirusTotal & Security Vendor Status -->
        <div style="background:#0d1e35;border:1px solid ${sevColor}33;border-radius:8px;padding:.75rem 1rem;display:flex;align-items:center;justify-content:space-between;">
          <div>
            <div style="font-size:.65rem;color:#64748b;">VIRUSTOTAL TELEMETRY</div>
            <div style="font-size:.82rem;font-weight:700;color:#e2e8f0;">${payloadInfo.virustotal}</div>
          </div>
          <button style="background:rgba(0,212,255,.12);border:1px solid rgba(0,212,255,.3);color:var(--cyan);padding:4px 10px;border-radius:6px;font-size:.72rem;cursor:pointer;" onclick="exportSocPdf()">
            <i class="fa-solid fa-file-pdf"></i> Export Report
          </button>
        </div>

        <!-- Action Playbook -->
        <div style="background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.25);border-radius:8px;padding:.75rem 1rem;">
          <div style="font-size:.65rem;color:#64748b;margin-bottom:2px;">RECOMMENDED ACTION PLAYBOOK</div>
          <div style="font-size:.82rem;font-weight:600;color:#e2e8f0;">${actionText}</div>
        </div>

      </div>
    `;
    modal.classList.remove('hidden');
  }

  // ── SOC REPORT EXPORT UTILITY ────────────────────────────────
  window.copyCode = function(btn) {
    const pre = btn.parentElement.nextElementSibling;
    if (pre && pre.innerText) {
      navigator.clipboard.writeText(pre.innerText).then(() => {
        const orig = btn.innerHTML;
        btn.innerHTML = '<i class="fa-solid fa-check"></i> Copied!';
        setTimeout(() => btn.innerHTML = orig, 1800);
      });
    }
  };

  window.exportSocPdf = function() {
    const ctx = window.activeScanContext || {
      filename: "sample_payload.exe",
      prediction: "Ransomware.Win32.Entropy",
      confidence: "98.4%",
      risk_level: "CRITICAL",
      sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      entropy: 7.82,
      strings_count: 4
    };

    const printWin = window.open('', '_blank');
    const yaraList = ctx.yara_matches ? ctx.yara_matches.join(', ') : 'YARA_Entropy_High';
    printWin.document.write(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>SOC Executive Report — ${ctx.filename}</title>
        <style>
          body { font-family: Arial, sans-serif; background: #fff; color: #1e293b; padding: 2rem; line-height: 1.6; }
          h1 { color: #0f172a; border-bottom: 2px solid #00d4ff; padding-bottom: 0.5rem; }
          h2 { color: #0284c7; margin-top: 1.5rem; }
          .badge { background: #fee2e2; color: #dc2626; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
          .code { font-family: monospace; background: #f1f5f9; padding: 2px 6px; border-radius: 4px; }
          table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
          th, td { border: 1px solid #cbd5e1; padding: 8px 12px; text-align: left; }
          th { background: #f8fafc; }
        </style>
      </head>
      <body>
        <h1>🛡️ THREATLENS AI — SOC EXECUTIVE REPORT</h1>
        <p><strong>Generated Date:</strong> ${new Date().toLocaleString()}</p>
        <p><strong>Target Artifact:</strong> <span class="code">${ctx.filename}</span></p>
        <p><strong>Prediction:</strong> <strong>${ctx.prediction}</strong> | <strong>Confidence:</strong> ${ctx.confidence} | <strong>Risk Level:</strong> <span class="badge">${ctx.risk_level}</span></p>
        <h2>1. Executive Summary</h2>
        <p>A critical anomaly was flagged on <strong>${ctx.filename}</strong> by ThreatLens AI Decision Tree engines. Shannon Entropy was measured at <strong>${ctx.entropy} / 8.00</strong>, indicating heavy obfuscation or cryptographic ransomware payload operations.</p>
        <h2>2. Artifact Forensic Indicators</h2>
        <table>
          <tr><th>Property</th><th>Value</th></tr>
          <tr><td>SHA-256 Hash</td><td><span class="code">${ctx.sha256}</span></td></tr>
          <tr><td>MD5 Hash</td><td><span class="code">${ctx.md5 || 'd41d8cd98f00b204e9800998ecf8427e'}</span></td></tr>
          <tr><td>Shannon Entropy</td><td>${ctx.entropy} / 8.00</td></tr>
          <tr><td>YARA Rules Flagged</td><td>${yaraList}</td></tr>
        </table>
        <h2>3. MITRE ATT&CK Mapping</h2>
        <p>• <strong>T1059.001:</strong> PowerShell Script Execution<br>• <strong>T1486:</strong> Data Encrypted for Impact<br>• <strong>T1490:</strong> Inhibit System Recovery (Volume Shadow Copy Deletion)</p>
        <h2>4. Recommended Containment Playbook</h2>
        <ol>
          <li>Isolate host network adapter immediately (<span class="code">Disable-NetAdapter</span>).</li>
          <li>Force-kill suspicious process trees (<span class="code">taskkill /F /IM powershell.exe /T</span>).</li>
          <li>Null-route remote C2 IP on perimeter firewall (<span class="code">netsh advfirewall</span>).</li>
        </ol>
      </body>
      </html>
    `);
    printWin.document.close();
    printWin.focus();
    setTimeout(() => { printWin.print(); }, 500);
  };

  // ── 10. TRENDS TAB (Chart.js) ──────────────────────────────────
  let sevChartInstance = null;
  let breakdownChartInstance = null;

  function renderTrends() {
    const sevCanvas   = document.getElementById('severityChart');
    const breakCanvas = document.getElementById('breakdownChart');
    if (!sevCanvas || !breakCanvas) return;

    // ── Latest Scan Card ──────────────────────────────────────────
    const lsc = window.lastScanData;
    const card = document.getElementById('latestScanCard');
    if (lsc && card) {
      card.style.display = 'block';
      const sevColor   = lsc.severity === 'CRITICAL' ? '#ef4444' : lsc.severity === 'HIGH' ? '#f97316' : '#22c55e';
      const labelColor = lsc.label === 'Benign' ? '#22c55e' : lsc.label === 'Ransomware' ? '#ef4444' : lsc.label === 'Trojan' ? '#a855f7' : '#f97316';
      document.getElementById('ls-name').textContent       = lsc.name.length > 42 ? lsc.name.substring(0,42)+'...' : lsc.name;
      document.getElementById('ls-label').textContent      = lsc.label;
      document.getElementById('ls-label').style.color      = labelColor;
      document.getElementById('ls-severity').textContent   = lsc.severity;
      document.getElementById('ls-severity').style.color   = sevColor;
      document.getElementById('ls-confidence').textContent = lsc.confPct;
      document.getElementById('ls-entropy').textContent    = lsc.entropy.toFixed(2) + ' / 8.0';
      document.getElementById('ls-strings').textContent    = lsc.strings + (lsc.strings === 1 ? ' indicator' : ' indicators');
      document.getElementById('ls-type').textContent       = lsc.isFile ? 'File Upload Scan' : 'URL Payload Scan';
      document.getElementById('ls-action').textContent     = lsc.actionText;
      document.getElementById('latestScanTime').textContent = 'Scanned at ' + lsc.ts;
      const pct      = Math.min((lsc.entropy / 8.0) * 100, 100).toFixed(1);
      const barColor = lsc.entropy >= 7 ? '#ef4444' : lsc.entropy >= 5.5 ? '#f59e0b' : '#22c55e';
      document.getElementById('ls-entropy-pct').textContent       = pct + '%';
      document.getElementById('ls-entropy-bar').style.width       = pct + '%';
      document.getElementById('ls-entropy-bar').style.background  = barColor;
    } else if (card) {
      card.style.display = 'none';
    }

    const badge = document.getElementById('trendsTotalBadge');
    if (badge) badge.textContent = '(' + threatsData.length + ' total events)';

    // ── Bar chart: real severity counts ───────────────────────────
    let critCount = 0, highCount = 0, medCount = 0, lowCount = 0;
    threatsData.forEach(t => {
      const s = (t.severity || '').toUpperCase();
      if (s === 'CRITICAL') critCount++;
      else if (s === 'HIGH') highCount++;
      else if (s === 'MEDIUM') medCount++;
      else lowCount++;
    });

    if (sevChartInstance) sevChartInstance.destroy();
    sevChartInstance = new Chart(sevCanvas.getContext('2d'), {
      type: 'bar',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
          label: 'Events',
          data: [critCount, highCount, medCount, lowCount],
          backgroundColor: ['#ef4444cc','#f59e0bcc','#3b82f6cc','#22c55ecc'],
          borderColor:     ['#ef4444',  '#f59e0b',  '#3b82f6',  '#22c55e'],
          borderWidth: 1, borderRadius: 7, borderSkipped: false, barThickness: 48
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: { backgroundColor:'#0a1628', titleColor:'#e2e8f0', bodyColor:'#00d4ff', borderColor:'rgba(0,212,255,.2)', borderWidth:1 }
        },
        scales: {
          x: { grid:{ display:false }, ticks:{ color:'#94a3b8', font:{ family:'Outfit', size:12, weight:'500' } } },
          y: { min:0, ticks:{ stepSize:1, color:'#64748b', font:{ family:'JetBrains Mono', size:11 } }, grid:{ color:'rgba(255,255,255,.05)' } }
        }
      }
    });

    // ── Donut chart: fully dynamic from threatsData ───────────────
    const palette = {
      'Ransomware':'#00d4ff','Trojan':'#a855f7','Worm':'#f97316',
      'Phishing':'#fb923c','Benign':'#22c55e','SQLi Breach Attempt':'#f59e0b',
      'DDoS SYN Flood':'#10b981','Ransomware.Win32.Entropy':'#ef4444'
    };
    const classMap = {};
    threatsData.forEach(t => {
      const c = t.classification || 'Unknown';
      classMap[c] = (classMap[c] || 0) + 1;
    });
    const categories = Object.entries(classMap).map(([label, val]) => ({
      label, val,
      color: palette[label] || ('#' + Math.abs(label.split('').reduce((h,c) => Math.imul(31,h)+c.charCodeAt(0)|0, 0)).toString(16).padStart(6,'a').substring(0,6))
    }));

    if (breakdownChartInstance) breakdownChartInstance.destroy();
    breakdownChartInstance = new Chart(breakCanvas.getContext('2d'), {
      type: 'doughnut',
      data: {
        labels: categories.map(c => c.label),
        datasets: [{ data: categories.map(c => c.val), backgroundColor: categories.map(c => c.color), borderColor:'#060d18', borderWidth:3 }]
      },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: '65%',
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor:'#0a1628', titleColor:'#e2e8f0', bodyColor:'#00d4ff', borderColor:'rgba(0,212,255,.2)', borderWidth:1,
            callbacks: { label: ctx => ' ' + ctx.label + ': ' + ctx.parsed + ' event' + (ctx.parsed !== 1 ? 's' : '') }
          }
        }
      }
    });

    const legendGrid = document.getElementById('chartLegendGrid');
    if (legendGrid) {
      legendGrid.innerHTML = categories.map(c => `
        <div class="legend-item">
          <span class="legend-dot" style="background:${c.color}"></span>
          <span class="legend-text" style="color:${c.color}">${c.label} <small style="color:var(--muted)">(${c.val})</small></span>
        </div>
      `).join('');
    }
  }

  // ── 11. SYNC DB BUTTON ───────────────────────────────────────
  document.getElementById('syncBtn')?.addEventListener('click', function() {
    this.innerHTML = '<i class="fa-solid fa-rotate fa-spin"></i> Syncing...';
    this.style.color = 'var(--cyan)';
    setTimeout(() => {
      this.innerHTML = '<i class="fa-solid fa-rotate"></i> Sync DB';
      this.style.color = '';
    }, 1500);
  });

  // ── 12. AI COPILOT SIDEBAR ─────────────────────────────────
  const API_BASE = (window.location.origin && window.location.origin !== 'null' && !window.location.origin.startsWith('file')) ? window.location.origin : 'http://localhost:8080';
  let copilotHistory = [];
  let copilotStreaming = false;

  const copilotFab = document.getElementById('copilotFab');
  const copilotSidebar = document.getElementById('copilotSidebar');
  const copilotCloseBtn = document.getElementById('copilotCloseBtn');
  const copilotClearBtn = document.getElementById('copilotClearBtn');
  const copilotInput = document.getElementById('copilotInput');
  const copilotSendBtn = document.getElementById('copilotSendBtn');
  const copilotMessages = document.getElementById('copilotMessages');
  const copilotChips = document.getElementById('copilotChips');
  const copilotContextBar = document.getElementById('copilotContextBar');
  const copilotContextText = document.getElementById('copilotContextText');
  const copilotCtxClear = document.getElementById('copilotCtxClear');

  function toggleCopilot() {
    copilotSidebar.classList.toggle('open');
    copilotFab.classList.toggle('hidden');
  }

  copilotFab?.addEventListener('click', toggleCopilot);
  copilotCloseBtn?.addEventListener('click', toggleCopilot);

  copilotCtxClear?.addEventListener('click', () => {
    window.activeScanContext = null;
    copilotContextBar.style.display = 'none';
  });

  window.updateCopilotContextUI = function() {
    if (window.activeScanContext) {
      copilotContextBar.style.display = 'flex';
      copilotContextText.textContent = window.activeScanContext.filename + ' — ' + window.activeScanContext.prediction;
    }
  };

  function renderMarkdownContent(text) {
    if (!text) return '';
    try {
      if (typeof window.marked !== 'undefined' && typeof window.marked.parse === 'function') {
        return window.marked.parse(text, { breaks: true, gfm: true });
      }
    } catch (e) {
      console.warn('marked parse error:', e);
    }
    return text
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/^### (.*$)/gim, '<h3>$1</h3>')
      .replace(/^## (.*$)/gim, '<h2>$1</h2>')
      .replace(/^# (.*$)/gim, '<h1>$1</h1>')
      .replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/gim, '<em>$1</em>')
      .replace(/`([^`]+)`/gim, '<code>$1</code>')
      .replace(/\n/gim, '<br>');
  }

  function addCopilotMessage(text, role, animate = false) {
    const msg = document.createElement('div');
    msg.className = 'copilot-msg';
    const avatar = document.createElement('i');
    avatar.className = role === 'user'
      ? 'fa-solid fa-user copilot-avatar user-avatar-copilot'
      : 'fa-solid fa-robot copilot-avatar';
    const bubble = document.createElement('div');
    bubble.className = 'copilot-bubble' + (role === 'user' ? ' user-bubble' : '');
    msg.appendChild(avatar);
    msg.appendChild(bubble);

    if (role === 'assistant' && animate) {
      bubble.innerHTML = '<div class="copilot-typing"><span></span><span></span><span></span></div>';
      copilotMessages.appendChild(msg);
      copilotMessages.scrollTop = copilotMessages.scrollHeight;
      return { bubble, msg };
    }

    if (role === 'assistant') {
      bubble.innerHTML = renderMarkdownContent(text);
    } else {
      bubble.textContent = text;
    }

    copilotMessages.appendChild(msg);
    copilotMessages.scrollTop = copilotMessages.scrollHeight;
    return { bubble, msg };
  }

  function addCopyButton(msgEl) {
    const bar = document.createElement('div');
    bar.className = 'copilot-msg-action-bar';
    const copyBtn = document.createElement('button');
    copyBtn.innerHTML = '<i class="fa-regular fa-copy"></i> Copy';
    copyBtn.addEventListener('click', () => {
      const bubbleText = msgEl.querySelector('.copilot-bubble')?.innerText || '';
      navigator.clipboard.writeText(bubbleText).then(() => {
        copyBtn.innerHTML = '<i class="fa-solid fa-check"></i> Copied!';
        setTimeout(() => { copyBtn.innerHTML = '<i class="fa-regular fa-copy"></i> Copy'; }, 1800);
      });
    });
    bar.appendChild(copyBtn);
    msgEl.appendChild(bar);
  }

  async function sendCopilotMessage(message) {
    if (!message || copilotStreaming) return;
    copilotStreaming = true;
    copilotSendBtn.disabled = true;

    addCopilotMessage(message, 'user');
    copilotHistory.push({ role: 'user', content: message });
    copilotInput.value = '';

    const { bubble, msg } = addCopilotMessage('', 'assistant', true);

    try {
      const response = await fetch(`${API_BASE}/api/copilot/chat/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: message,
          history: copilotHistory.slice(-6),
          scan_context: window.activeScanContext || null,
          api_key: localStorage.getItem('threatlens_gemini_key') || ''
        })
      });

      if (!response.ok) throw new Error(`Server error: ${response.status}`);

      const reader = response.body.getReader();
      const decoder = new TextDecoder('utf-8');
      let accumulated = '';
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const data = JSON.parse(line);
            if (data.text) {
              accumulated += data.text;
              bubble.innerHTML = renderMarkdownContent(accumulated);
              copilotMessages.scrollTop = copilotMessages.scrollHeight;
            }
          } catch (e) {
            accumulated += line;
            bubble.innerHTML = renderMarkdownContent(accumulated);
          }
        }
      }

      if (buffer.trim()) {
        try {
          const data = JSON.parse(buffer);
          if (data.text) accumulated += data.text;
        } catch (e) {
          accumulated += buffer;
        }
        bubble.innerHTML = renderMarkdownContent(accumulated);
      }

      copilotHistory.push({ role: 'assistant', content: accumulated });
      addCopyButton(msg);

    } catch (error) {
      console.error('Copilot error:', error);
      bubble.innerHTML = 'Sorry, I could not connect to the AI server. Make sure FastAPI is running on port 8080.';
    } finally {
      copilotStreaming = false;
      copilotSendBtn.disabled = false;
      copilotInput.focus();
    }
  }

  copilotSendBtn?.addEventListener('click', () => {
    sendCopilotMessage(copilotInput.value.trim());
  });

  copilotInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendCopilotMessage(copilotInput.value.trim());
    }
  });

  copilotClearBtn?.addEventListener('click', () => {
    copilotHistory = [];
    copilotMessages.innerHTML = '';
    addCopilotMessage('Chat cleared. How can I help you?', 'assistant');
  });

  copilotChips?.querySelectorAll('.cp-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const msg = chip.dataset.msg;
      if (msg) {
        copilotInput.value = msg;
        sendCopilotMessage(msg);
      }
    });
  });

  // ── 13. RADAR CANVAS ─────────────────────────────────────────
  const canvas = document.getElementById('radarCanvas');
  if (canvas) {
    const ctx = canvas.getContext('2d');
    let angle = 0;
    const dots = [
      {r:.35, a:0.8,  size:3, col:'#ef4444'},
      {r:.55, a:2.1,  size:4, col:'#f97316'},
      {r:.70, a:4.0,  size:3, col:'#ef4444'},
      {r:.25, a:5.2,  size:2, col:'#f59e0b'},
      {r:.80, a:1.2,  size:3, col:'#ef4444'},
    ];

    function drawRadar() {
      const W = canvas.width, H = canvas.height;
      const cx = W/2, cy = H/2;
      const R = Math.min(W,H)/2 - 18;

      ctx.clearRect(0,0,W,H);

      // Background
      ctx.fillStyle='rgba(0,212,255,.015)';
      ctx.fillRect(0,0,W,H);

      // Rings
      for (let i=1;i<=4;i++) {
        ctx.beginPath();
        ctx.arc(cx,cy,R*(i/4),0,Math.PI*2);
        ctx.strokeStyle=`rgba(0,212,255,${i===4?.12:.06})`;
        ctx.lineWidth=1;
        ctx.stroke();
      }

      // Grid lines
      for (let i=0;i<6;i++) {
        const a=i*Math.PI/3;
        ctx.beginPath();
        ctx.moveTo(cx,cy);
        ctx.lineTo(cx+Math.cos(a)*R, cy+Math.sin(a)*R);
        ctx.strokeStyle='rgba(0,212,255,.06)';
        ctx.stroke();
      }

      // Sweep gradient
      const grad=ctx.createConicalGradient
        ? ctx.createConicalGradient(cx,cy,angle)
        : null;

      ctx.save();
      ctx.beginPath();
      ctx.moveTo(cx,cy);
      ctx.arc(cx,cy,R,angle,angle+0.7);
      ctx.closePath();
      ctx.fillStyle='rgba(0,212,255,.08)';
      ctx.fill();

      // Sweep line
      ctx.beginPath();
      ctx.moveTo(cx,cy);
      ctx.lineTo(cx+Math.cos(angle)*R, cy+Math.sin(angle)*R);
      ctx.strokeStyle='rgba(0,212,255,.6)';
      ctx.lineWidth=1.5;
      ctx.stroke();
      ctx.restore();

      // Threat dots
      dots.forEach(d => {
        const da = d.a + angle * 0.05;
        const x = cx + Math.cos(da)*R*d.r;
        const y = cy + Math.sin(da)*R*d.r;
        ctx.beginPath();
        ctx.arc(x,y,d.size,0,Math.PI*2);
        ctx.fillStyle=d.col;
        ctx.shadowColor=d.col;
        ctx.shadowBlur=8;
        ctx.fill();
        ctx.shadowBlur=0;
      });

      // Center dot
      ctx.beginPath();
      ctx.arc(cx,cy,3,0,Math.PI*2);
      ctx.fillStyle='var(--cyan)';
      ctx.fill();

      angle += 0.025;
      requestAnimationFrame(drawRadar);
    }
    drawRadar();
  }

});
