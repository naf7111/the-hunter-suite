import re
import os
import requests
import random
import webbrowser
import html
import logging
from datetime import datetime
from urllib.parse import urljoin, urlparse

# اعداد السجلات
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# اعدادات المتصفح والارتباطات
USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"]
session = requests.Session()
session.headers.update({'User-Agent': random.choice(USER_AGENTS)})

# الاعدادات العامة للبرنامج
GLOBAL_CONFIG = {
    "verify_ssl": True,
    "timeout": (3, 10),
    "known_services": ['rollbar', 'sentry', 'google-analytics', 'googletagmanager', 'webpack', 'jquery'],
    "custom_keywords": []
}

def print_banner():
    print("\n" + "=" * 100)
    print("THE HUNTER SECURITY SUITE v22.0 - ULTIMATE CUSTOM EDITION")
    print("Custom Keyword Detection | Modular Recon | Hardened Reports | No Emojis")
    print("=" * 100)

def normalize_url(url):
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url

def safe_get(url):
    try:
        r = session.get(
            url, 
            timeout=GLOBAL_CONFIG["timeout"], 
            verify=GLOBAL_CONFIG["verify_ssl"]
        )
        return r
    except Exception as e:
        logging.error(f"Request failed for {url}: {e}")
        return None

def process_finding(text):
    is_known = any(s in text.lower() for s in GLOBAL_CONFIG["known_services"])
    escaped = html.escape(text)
    
    suspicious_patterns = [r'<script', r'javascript:', r'onerror=', r'eval\(', r'document\.write']
    is_suspicious = any(re.search(p, text, re.IGNORECASE) for p in suspicious_patterns)
    
    if is_suspicious:
        if is_known:
            return "KNOWN", f'<div style="color: #94a3b8; font-size: 0.8em;">KNOWN SERVICE:</div><span style="color: #38bdf8;">{escaped}</span>'
        return "SUSPICIOUS", f'<div class="alert-box">POTENTIAL INJECTION DETECTED:</div><span class="bad-code">{escaped}</span>'
    return "NORMAL", escaped

# --- الموديولات البرمجية ---

def js_analyzer_module(content):
    findings = {"Secrets": [], "Third-Party": [], "Suspicious": [], "Custom Keywords": []}
    
    # البحث عن الكلمات المخصصة سطر بسطر
    if GLOBAL_CONFIG["custom_keywords"]:
        for line in content.splitlines():
            for kw in GLOBAL_CONFIG["custom_keywords"]:
                if kw.lower() in line.lower():
                    findings["Custom Keywords"].append(f"Match found: {html.escape(line.strip()[:150])}")

    patterns = {
        "Secrets": [r'(?i)(?:password|secret|bearer|token|aws_key)\s*[:=]\s*["\']([^"\']{8,})["\']'],
        "Suspicious": [r'eval\(.*?\)', r'document\.write\(.*?\)', r'javascript:[^\s"\']+', r'<script[\s\S]*?>']
    }
    for cat, p_list in patterns.items():
        for p in p_list:
            for m in re.findall(p, content):
                type_, formatted = process_finding(m)
                if type_ == "KNOWN": findings["Third-Party"].append(formatted)
                elif type_ == "SUSPICIOUS": findings["Suspicious"].append(formatted)
                else: findings["Secrets"].append(formatted)
    return findings

def link_finder_module(content):
    pattern = r'["\']((?:/|[a-z]+://)[a-z0-9/._?=&%-]{3,})["\']'
    links = sorted(list(set(re.findall(pattern, content))))
    return {"Endpoints": [html.escape(l) for l in links]}

def headers_audit_module(url):
    results = []
    r = safe_get(url)
    if r:
        checks = {'Content-Security-Policy': 'XSS Protection', 'X-Frame-Options': 'Clickjacking', 'Strict-Transport-Security': 'HSTS'}
        for h, desc in checks.items():
            val = r.headers.get(h)
            status = f"PRESENT: {html.escape(val)}" if val else "MISSING"
            results.append(f"{h} ({desc}): {status}")
    return {"Headers Audit": results}

def tech_fingerprint_module(url):
    techs = []
    r = safe_get(url)
    if r:
        server = html.escape(r.headers.get('Server', 'Unknown'))
        powered = html.escape(r.headers.get('X-Powered-By', 'N/A'))
        techs.extend([f"Server: {server}", f"Powered By: {powered}"])
        body = r.text.lower()
        if 'wp-content' in body: techs.append("CMS: WordPress Detected")
        if 'react' in body: techs.append("Framework: React Detected")
    return {"Tech Stack": techs}

def leak_scanner_module(domain):
    found = []
    files = ['.git/config', '.env', 'robots.txt', '.git/HEAD']
    for f in files:
        target = f"https://{domain}/{f}"
        r = safe_get(target)
        if r and r.status_code == 200:
            found.append(f"ACCESSIBLE: {html.escape(target)}")
    return {"Sensitive Leaks": found if found else ["No leaks detected"]}

# --- محرك التقارير ---

def generate_report(target, data):
    report_file = f"Hunter_Final_Report_{datetime.now().strftime('%H%M%S')}.html"
    html_content = f"""
    <html><head><style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #f1f5f9; padding: 20px; }}
        .card {{ background: #1e293b; padding: 20px; border-radius: 10px; margin-bottom: 20px; border: 1px solid #334155; }}
        .alert-box {{ color: #fbbf24; font-weight: bold; font-size: 0.8em; }}
        .bad-code {{ color: #f87171; background: #450a0a; padding: 5px; border-radius: 4px; display: block; }}
        pre {{ background: #000; color: #34d399; padding: 12px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; border-left: 4px solid #38bdf8; }}
        h3 {{ color: #38bdf8; border-bottom: 1px solid #334155; padding-bottom: 5px; }}
    </style></head><body>
    <h1>Security Audit Report: {html.escape(target)}</h1>
    <p>Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    """
    for src, mods in data.items():
        html_content += f"<div class='card'><h2>Source: {html.escape(src)}</h2>"
        for m_name, findings in mods.items():
            if findings:
                html_content += f"<h3>{m_name}</h3><pre>{'<br>'.join(findings)}</pre>"
        html_content += "</div>"
    html_content += "</body></html>"
    with open(report_file, 'w', encoding='utf-8') as f: f.write(html_content)
    print(f"\n[+] Analysis complete. Report generated: {report_file}")
    webbrowser.open("file://" + os.path.realpath(report_file))

# --- النظام الرئيسي ---

def main():
    while True:
        print_banner()
        current_keywords = ", ".join(GLOBAL_CONFIG["custom_keywords"]) if GLOBAL_CONFIG["custom_keywords"] else "None"
        print(f"SETTINGS: SSL={GLOBAL_CONFIG['verify_ssl']} | Keywords=[{current_keywords}]")
        print("\n[1] JS Security Analysis")
        print("[2] Links and Endpoints Finder")
        print("[3] Security Headers Audit")
        print("[4] Technology Fingerprinting")
        print("[5] Sensitive Files Leaks")
        print("[6] Configuration Settings (SSL/Keywords/Proxy)")
        print("[0] Exit Program")
        
        choice = input("\nSelect Module: ")
        
        if choice == '0': break
        
        if choice == '6':
            # إدارة الإعدادات والكلمات المفتاحية
            sub_opt = input("\n[1] Toggle SSL [2] Set Keywords [3] Proxy Config: ")
            if sub_opt == '1':
                GLOBAL_CONFIG["verify_ssl"] = not GLOBAL_CONFIG["verify_ssl"]
            elif sub_opt == '2':
                kws = input("Enter keywords separated by comma: ")
                GLOBAL_CONFIG["custom_keywords"] = [k.strip() for k in kws.split(',') if k.strip()]
            elif sub_opt == '3':
                p_choice = input("Enable Proxy (127.0.0.1:8080)? (y/n): ")
                if p_choice.lower() == 'y':
                    session.proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
                else: session.proxies = {}
            continue

        target = input("Enter Target (URL/Domain/Path): ").strip()
        if not os.path.isfile(target): target = normalize_url(target)
        
        results = {}
        if choice == '1':
            if os.path.isfile(target):
                with open(target, 'r', encoding='utf-8', errors='ignore') as f:
                    results[target] = js_analyzer_module(f.read())
            else:
                r = safe_get(target)
                if r:
                    scripts = re.findall(r'<script[^>]+src=["\']([^"\'>]+)["\']', r.text)
                    for s in set(scripts):
                        u = urljoin(target, s)
                        js_r = safe_get(u)
                        if js_r: results[u] = js_analyzer_module(js_r.text)
        
        elif choice == '2':
            r = safe_get(target)
            if r: results[target] = link_finder_module(r.text)
            
        elif choice == '3':
            results[target] = headers_audit_module(target)
            
        elif choice == '4':
            results[target] = tech_fingerprint_module(target)
            
        elif choice == '5':
            domain = urlparse(target).netloc or target
            results[domain] = leak_scanner_module(domain)

        if results: generate_report(target, results)
        input("\nPress Enter to return to menu...")

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Process terminated.")
