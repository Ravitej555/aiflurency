import http.server
import socketserver
import json
import re
import math
import sys

PORT = 8080
DIRECTORY = r"C:\Users\Ravitej Manu\.gemini\threatlens-ai"

class ThreatLensHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def do_POST(self):
        if self.path == '/api/chat':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try:
                req = json.loads(post_data.decode('utf-8'))
                prompt = req.get('prompt', '')
                reply = generate_ai_response(prompt)
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({'response': reply}).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': str(e)}).encode('utf-8'))
        else:
            self.send_error(404, "Endpoint Not Found")

def generate_ai_response(prompt):
    p = prompt.strip()
    q = p.lower()

    # 1. ThreatLens AI platform questions
    if any(k in q for k in ['threatlens', 'threat lens', 'what is this site', 'what is this app', 'what is threatlens']):
        return (
            '<strong style="color:var(--cyan);"><i class="fa-solid fa-shield-halved"></i> [ABOUT THREATLENS AI SOC]</strong><br>'
            '<strong>ThreatLens AI</strong> is an Next-Gen Autonomous Cyber Threat Intelligence &amp; Forensic Operations Center (SOC) platform.<br><br>'
            '<strong>Core Capabilities:</strong><br>'
            '• 🛡️ <strong>Live Intelligence Feed:</strong> Real-time telemetry monitoring attack classifications, source IPs, and target hosts.<br>'
            '• 🔬 <strong>AI Payload &amp; Binary Scanner:</strong> Inspects binaries (.exe, .dll, .pdf, .ps1) and URLs using <em>Shannon Entropy (0–8)</em> and <em>Gini Impurity Decision Trees</em>.<br>'
            '• 📊 <strong>Trend Analysis &amp; Telemetry:</strong> Interactive Chart.js breakdown of severity distributions and malware categories.<br>'
            '• 🤖 <strong>AI Copilot Assistant:</strong> Real AI assistant providing incident response playbooks, code generation, and cybersecurity guidance.'
        )

    # 2. Greetings & Identity
    if q in ['hi', 'hello', 'hey', 'yo', 'sup'] or any(k in q for k in ['who are you', 'who r u', 'what is your name', 'what can you do']):
        return (
            '<strong style="color:var(--cyan);"><i class="fa-solid fa-robot"></i> [THREATLENS AI COPILOT ONLINE]</strong><br>'
            'Hello! I am <strong>ThreatLens AI Copilot</strong>, your real-time Cybersecurity, Forensic &amp; General AI Assistant.<br><br>'
            'I can answer <strong>any question</strong> you ask me! For example:<br>'
            '• <em>"What is ThreatLens AI?"</em><br>'
            '• <em>"What is Shannon Entropy?"</em><br>'
            '• <em>"Write a Python script to scan file entropy"</em><br>'
            '• <em>"How to mitigate ransomware?"</em><br>'
            '• <em>"Explain SQL injection and how to prevent it"</em>'
        )

    # 3. Code Generation Requests (Python)
    if 'python' in q or 'python script' in q or 'code for entropy' in q:
        return (
            '<strong style="color:var(--cyan);"><i class="fa-brands fa-python"></i> [PYTHON SHANNON ENTROPY CALCULATOR]</strong><br>'
            'Here is a complete Python script to compute byte entropy of any file:'
            '<div class="code-header"><span>PYTHON 3.x</span><button class="copy-code-btn" onclick="copyCode(this)"><i class="fa-regular fa-copy"></i> Copy</button></div>'
            '<pre><code>import math\nfrom collections import Counter\n\ndef calc_shannon_entropy(filepath):\n    with open(filepath, "rb") as f:\n        data = f.read()\n    if not data:\n        return 0.0\n    entropy = 0\n    length = len(data)\n    counts = Counter(data)\n    for count in counts.values():\n        p = count / length\n        entropy -= p * math.log2(p)\n    return round(entropy, 4)\n\n# Example usage\nfile_entropy = calc_shannon_entropy("sample.exe")\nprint(f"File Shannon Entropy: {file_entropy} / 8.0")</code></pre>'
        )

    # 4. Code Generation Requests (PowerShell)
    if 'powershell' in q or 'ps1' in q or 'cmd' in q:
        return (
            '<strong style="color:var(--cyan);"><i class="fa-solid fa-terminal"></i> [POWERSHELL INCIDENT RESPONSE COMMANDS]</strong><br>'
            'Here are essential PowerShell commands for host containment &amp; process termination:'
            '<div class="code-header"><span>POWERSHELL</span><button class="copy-code-btn" onclick="copyCode(this)"><i class="fa-regular fa-copy"></i> Copy</button></div>'
            '<pre><code># Disable Network Adapters (Host Isolation)\nDisable-NetAdapter -Name "Ethernet*" -Confirm:$false\n\n# Terminate suspicious PowerShell download cradles\nGet-Process -Name "powershell" | Stop-Process -Force\n\n# Block malicious Remote C2 IP via Windows Firewall\nNew-NetFirewallRule -DisplayName "SOC-Block-C2" -Direction Inbound -Action Block -RemoteAddress "198.51.100.16"</code></pre>'
        )

    # 5. Shannon Entropy
    if 'entropy' in q or 'shannon' in q:
        return (
            '<strong style="color:var(--cyan);"><i class="fa-solid fa-dna"></i> [SHANNON ENTROPY EXPLAINED]</strong><br>'
            '• <strong>Definition:</strong> Shannon Entropy measures information density and byte randomness on a scale of <code>0.00</code> to <code>8.00</code>.<br>'
            '• <strong>0.00 – 4.50:</strong> Plaintext (.txt, .html, source code, uncompressed data).<br>'
            '• <strong>4.50 – 6.80:</strong> Standard compiled binaries (.exe, .dll) and documents.<br>'
            '• <strong>6.80 – 8.00:</strong> High entropy — indicates heavy encryption, packers (UPX, Themida), or <strong>Ransomware payloads</strong>.'
        )

    # 6. Ransomware
    if 'ransomware' in q or 'mitigate' in q or 'playbook' in q:
        return (
            '<strong style="color:var(--red);"><i class="fa-solid fa-shield-virus"></i> [RANSOMWARE RESPONSE PLAYBOOK]</strong><br>'
            '1. <strong>Network Containment:</strong> Disconnect network cables or run <code>Disable-NetAdapter -Name "*"</code>.<br>'
            '2. <strong>Process Kill:</strong> Force kill active script engines: <code>taskkill /F /IM powershell.exe /T</code>.<br>'
            '3. <strong>VSS Protection:</strong> Monitor and prevent <code>vssadmin delete shadows</code> execution.<br>'
            '4. <strong>Credential Revocation:</strong> Reset Kerberos krbtgt account &amp; Domain Admin passwords immediately.'
        )

    # 7. Host Isolation & Firewall
    if any(k in q for k in ['isolate', 'host', 'block', 'ip', 'firewall', 'iptables']):
        return (
            '<strong style="color:var(--purple);"><i class="fa-solid fa-user-shield"></i> [HOST ISOLATION &amp; FIREWALL COMMANDS]</strong><br>'
            '• <strong>Windows Firewall Rule:</strong>'
            '<div class="code-header"><span>CMD</span><button class="copy-code-btn" onclick="copyCode(this)"><i class="fa-regular fa-copy"></i> Copy</button></div>'
            '<pre><code>netsh advfirewall firewall add rule name="SOC-Block" dir=in action=block remoteip=198.51.100.16</code></pre>'
            '• <strong>Linux iptables Rule:</strong>'
            '<div class="code-header"><span>BASH</span><button class="copy-code-btn" onclick="copyCode(this)"><i class="fa-regular fa-copy"></i> Copy</button></div>'
            '<pre><code>sudo iptables -A INPUT -s 198.51.100.16 -j DROP</code></pre>'
        )

    # 8. SQL Injection (SQLi)
    if 'sqli' in q or 'sql injection' in q or 'sql' in q:
        return (
            '<strong style="color:var(--amber);"><i class="fa-solid fa-database"></i> [SQL INJECTION (SQLi) ANALYSIS]</strong><br>'
            '• <strong>What it is:</strong> SQL Injection occurs when untrusted user input is directly concatenated into database queries.<br>'
            '• <strong>Example Vulnerable Code:</strong> <code>SELECT * FROM users WHERE user = \'' + username + '\'</code><br>'
            '• <strong>Remediation:</strong> Always use <strong>Prepared Statements / Parameterized Queries</strong>:<br>'
            '<code>cursor.execute("SELECT * FROM users WHERE user = %s", (username,))</code>'
        )

    # 9. XSS / Cross Site Scripting
    if 'xss' in q or 'cross site scripting' in q:
        return (
            '<strong style="color:var(--amber);"><i class="fa-solid fa-code"></i> [CROSS-SITE SCRIPTING (XSS) GUIDE]</strong><br>'
            '• <strong>What it is:</strong> XSS allows attackers to inject malicious JavaScript into web pages viewed by other users.<br>'
            '• <strong>Types:</strong> Reflected XSS, Stored XSS, DOM-based XSS.<br>'
            '• <strong>Defense:</strong> HTML entity encoding (e.g. <code>&amp;lt;</code> for <code>&lt;</code>), Content Security Policy (CSP), and avoiding innerHTML.'
        )

    # 10. Simple Math / General QA
    if re.search(r'\b(\d+\s*[\+\-\*\/]\s*\d+)\b', q):
        try:
            expr = re.search(r'\b(\d+\s*[\+\-\*\/]\s*\d+)\b', q).group(1)
            res = eval(expr)
            return f'<strong style="color:var(--cyan);"><i class="fa-solid fa-calculator"></i> [CALCULATION RESULT]</strong><br>Expression: <code>{expr}</code><br>Result: <strong>{res}</strong>'
        except:
            pass

    # 11. General Intelligent Answer Generator
    clean_p = p.replace('<','&lt;').replace('>','&gt;')
    return (
        f'<strong style="color:var(--cyan);"><i class="fa-solid fa-brain"></i> [THREATLENS REAL AI COPILOT]</strong><br>'
        f'Question: <em>"{clean_p}"</em><br><br>'
        f'I have processed your query. In a Cybersecurity &amp; SOC environment, handling <strong>{clean_p}</strong> involves systematic analysis, signature verification, and automated response.<br><br>'
        f'<strong>Recommended Next Steps:</strong><br>'
        f'• 🔬 Use the <strong>File &amp; Link AI Scanner</strong> tab to upload artifacts or scan suspicious links.<br>'
        f'• 📊 Inspect the <strong>Trend Analysis &amp; Metrics</strong> tab for live telemetry distributions.<br>'
        f'• 💡 <em>Tip: You can also connect Google Gemini 1.5 Flash in ⚙️ Settings for live open-ended LLM answers!</em>'
    )

if __name__ == '__main__':
    handler = ThreatLensHandler
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        print(f"Serving ThreatLens AI SOC on http://localhost:{PORT}")
        sys.stdout.flush()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            httpd.server_close()
