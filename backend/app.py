"""
app.py - OSINT Recon Automation Toolkit (Flask backend)
Modified to minimize import dependencies and use subprocess calls

Features:
- /api/recon?target=example.com&use_spiderfoot=1 -> runs full recon including SpiderFoot
- /api/status/<job_id> -> get status (in-memory job store)
- Outputs saved under ./outputs/<target>/

Notes:
- Only run against targets you are authorized to test.
- Use a .env file to store API keys (RECON_ALLOWED_KEY, SHODAN_API_KEY, GITHUB_TOKEN, CENSYS_ID, CENSYS_SECRET)
"""
import sys
import os
import re
import json
import csv
import socket
import time
import threading
import traceback
import tempfile
import subprocess
from datetime import datetime, timezone
from queue import Queue
import signal
import time as time_module

# Core Flask imports (required)
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from io import BytesIO
try:
    from pdf_export import render_report_pdf
except Exception:
    render_report_pdf = None

# Dynamic imports with fallbacks
def safe_import(module_name, package=None):
    """Safely import a module, return None if not available"""
    try:
        if package:
            return __import__(f"{package}.{module_name}", fromlist=[module_name])
        return __import__(module_name)
    except ImportError:
        return None

# Load modules dynamically
requests = safe_import('requests')
whois_module = safe_import('whois')
dns_resolver = None
try:
    dns_module = safe_import('dns.resolver')
    if dns_module:
        dns_resolver = dns_module
except:
    pass

builtwith = safe_import('builtwith')
shodan = safe_import('shodan')
sublist3r = safe_import('sublist3r')

# Load environment variables
dotenv = safe_import('dotenv')
if dotenv:
    try:
        dotenv.load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))
    except:
        pass

# -------------------------
# Configuration
# -------------------------
OUTPUT_DIR = "outputs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

AUTHORIZATION_KEY = os.environ.get("RECON_ALLOWED_KEY")
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
CENSYS_ID = os.environ.get("CENSYS_ID")
CENSYS_SECRET = os.environ.get("CENSYS_SECRET")
PORT = int(os.environ.get("PORT", 5000))

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389,
             443, 445, 465, 587, 636, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

DEFAULT_WORDS = ["www", "mail", "webmail", "smtp", "admin", "portal", "dev", "test",
                 "api", "beta", "shop", "m", "staging", "git", "docs"]

app = Flask(__name__)
CORS(app)

# -------------------------
# Utility functions
# -------------------------
def require_authorization(req):
    # Authorization disabled: public API endpoints (no key required)
    return True, None

def save_output(target, data):
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", target)
    outdir = os.path.join(OUTPUT_DIR, safe)
    os.makedirs(outdir, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    json_path = os.path.join(outdir, f"recon_{timestamp}.json")
    with open(json_path, "w") as f:
        json.dump(data, f, indent=2)

    csv_path = os.path.join(outdir, f"summary_{timestamp}.csv")
    with open(csv_path, "w", newline="") as csvf:
        writer = csv.writer(csvf)
        writer.writerow(["hostname", "ip", "open_ports", "services"])
        for h in data.get("hosts", []):
            writer.writerow([
                h.get("hostname"), ",".join(h.get("ips", [])), ",".join(str(p) for p in h.get("open_ports", [])),
                ";".join(h.get("services", []))
            ])
    return json_path, csv_path

def normalized_domain(target):
    t = target.strip()
    t = re.sub(r"^https?://", "", t)
    t = t.split("/")[0]
    return t.lower()

def format_duration(seconds):
    """Format duration in seconds to human readable format"""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        mins = seconds // 60
        secs = seconds % 60
        return f"{mins}m {secs}s"
    else:
        hours = seconds // 3600
        mins = (seconds % 3600) // 60
        return f"{hours}h {mins}m"

def dns_resolve(hostname, timeout=3.0):
    ips = set()
    print(f"Resolving DNS for {hostname}")

    # Try using dns.resolver if available
    if dns_resolver:
        try:
            resolver = dns_resolver.Resolver()
            resolver.lifetime = timeout
            try:
                answers = resolver.resolve(hostname, "A")
                for r in answers:
                    ip = r.to_text()
                    ips.add(ip)
                    print(f"Resolved A record: {ip}")
            except:
                pass
            try:
                answers = resolver.resolve(hostname, "AAAA")
                for r in answers:
                    ip = r.to_text()
                    ips.add(ip)
                    print(f"Resolved AAAA record: {ip}")
            except:
                pass
        except Exception as e:
            print(f"DNS resolver failed for {hostname}: {str(e)}")

    # Fallback to subprocess dig
    if not ips:
        try:
            result = subprocess.run(['dig', '+short', hostname, 'A'], capture_output=True, text=True, timeout=timeout)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    line = line.strip()
                    if line and line.count('.') == 3 and not line.startswith(';'):
                        ips.add(line)
                        print(f"Resolved A record via dig: {line}")
                # Try AAAA records
                result_aaaa = subprocess.run(['dig', '+short', hostname, 'AAAA'], capture_output=True, text=True, timeout=timeout)
                if result_aaaa.returncode == 0:
                    lines = result_aaaa.stdout.split('\n')
                    for line in lines:
                        line = line.strip()
                        if line and ':' in line and not line.startswith(';'):
                            ips.add(line)
                            print(f"Resolved AAAA record via dig: {line}")
        except FileNotFoundError:
            print(f"dig command not available for {hostname}")
        except Exception as e:
            print(f"dig subprocess failed for {hostname}: {str(e)}")

    # Fallback to socket
    if not ips:
        try:
            ip = socket.gethostbyname(hostname)
            ips.add(ip)
            print(f"Resolved via socket: {ip}")
        except Exception as e:
            print(f"Socket resolution failed for {hostname}: {str(e)}")

    if not ips:
        print(f"No IPs resolved for {hostname}")
    return list(ips)

def whois_lookup(domain):
    if whois_module:
        try:
            w = whois_module.whois(domain)
            return {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "whois": str(w),
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "emails": w.emails,
                "nets": w.nets if hasattr(w, 'nets') else None,
                "cidr": w.cidr if hasattr(w, 'cidr') else None
            }
        except Exception as e:
            print(f"WHOIS lookup failed for {domain}: {str(e)}")
    
    # Fallback to subprocess whois
    try:
        result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return {"whois": result.stdout, "source": "subprocess"}
    except Exception as e:
        print(f"Subprocess whois failed for {domain}: {str(e)}")
    
    return {"error": "WHOIS not available"}

def crt_sh_subdomains(domain):
    if not requests:
        return []
    
    found = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        print(f"Querying crt.sh for {domain}")
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            try:
                arr = r.json()
                for entry in arr:
                    name = entry.get("name_value")
                    if not name:
                        continue
                    for n in str(name).splitlines():
                        if n.endswith(domain):
                            found.add(n.lower())
            except ValueError:
                txt = r.text
                for match in re.findall(r'>([\w\-\._]+\.' + re.escape(domain) + r')<', txt):
                    found.add(match.lower())
        else:
            print(f"crt.sh request failed for {domain}: status {r.status_code}")
    except Exception as e:
        print(f"crt.sh error for {domain}: {str(e)}")
    return sorted(found)

def dns_bruteforce(domain, wordlist=None, threads=10):
    if wordlist is None:
        wordlist = DEFAULT_WORDS
    found = []
    q = Queue()
    for w in wordlist:
        q.put(w)
    lock = threading.Lock()

    def worker():
        while not q.empty():
            try:
                n = q.get_nowait()
            except Exception:
                return
            host = f"{n}.{domain}"
            ips = dns_resolve(host)
            if ips:
                with lock:
                    found.append((host, ips))
            q.task_done()

    threads_list = []
    for _ in range(min(threads, len(wordlist))):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads_list.append(t)

    q.join()
    return found

def simple_port_scan(ip, ports=None, timeout=2.0):
    if ports is None:
        ports = TOP_PORTS
    open_ports = []
    services = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            result = s.connect_ex((ip, p))
            if result == 0:
                try:
                    s.settimeout(0.8)
                    s.sendall(b"\r\n")
                    banner = s.recv(512)
                    banner_text = banner.decode(errors="ignore").strip()
                except Exception:
                    banner_text = ""
                open_ports.append(p)
                services.append({"port": p, "banner": banner_text})
        except Exception as e:
            print(f"Socket error for {ip}:{p}: {str(e)}")
        finally:
            try:
                s.close()
            except Exception:
                pass
    return open_ports, services

def detect_techstack_from_url(url):
    tech = {}
    if builtwith:
        try:
            tech = builtwith.parse(url)
            return tech
        except Exception as e:
            print(f"Builtwith failed for {url}: {str(e)}")
    
    if requests:
        try:
            r = requests.get(url, timeout=6)
            tech = {"headers_guess": dict(r.headers)}
        except Exception as e:
            print(f"Tech stack detection failed for {url}: {str(e)}")
            tech = {"error": str(e)}
    else:
        tech = {"error": "requests module not available"}
    return tech

def github_search_code(domain, token=None, max_results=30):
    if not requests:
        return []
    
    results = []
    headers = {"User-Agent": "ReconToolkit/1.0"}
    if token:
        headers["Authorization"] = f"token {token}"
        try:
            q = f'"{domain}" in:file'
            url = "https://api.github.com/search/code"
            params = {"q": q, "per_page": max_results}
            print(f"Querying GitHub for {domain}")
            r = requests.get(url, headers=headers, params=params, timeout=10)
            if r.status_code == 200:
                data = r.json()
                for item in data.get("items", [])[:max_results]:
                    results.append({
                        "path": item.get("path"),
                        "repository": item.get("repository", {}).get("full_name"),
                        "url": item.get("html_url")
                    })
                return results
        except Exception as e:
            print(f"GitHub search error for {domain}: {str(e)}")
    
    # Fallback web search
    try:
        q = f'{domain} "password" OR "secret" OR "api_key" OR "aws_secret"'
        url = f"https://github.com/search?q={requests.utils.quote(q)}&type=code"
        print(f"Querying GitHub fallback for {domain}")
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            html = r.text
            for match in re.findall(r'href="(/[^/]+/[^/]+/blob/[^"]+)"', html)[:max_results]:
                results.append({"url": "https://github.com" + match})
    except Exception as e:
        print(f"GitHub fallback search error for {domain}: {str(e)}")
    return results

def pastebin_search(domain, max_results=10):
    if not requests:
        return []
    
    finds = []
    try:
        url = f"https://pastebin.com/search?q={requests.utils.quote(domain)}"
        print(f"Querying Pastebin for {domain}")
        r = requests.get(url, timeout=8, headers={"User-Agent": "ReconToolkit/1.0"})
        if r.status_code == 200:
            html = r.text
            for m in re.findall(r'href="/([A-Za-z0-9]{8})"', html):
                finds.append("https://pastebin.com/raw/" + m)
                if len(finds) >= max_results:
                    break
    except Exception as e:
        print(f"Pastebin search error for {domain}: {str(e)}")
    
    results = []
    for u in finds:
        try:
            print(f"Fetching Pastebin content from {u}")
            r = requests.get(u, timeout=6)
            if r.status_code == 200 and domain in r.text:
                results.append({"url": u, "snippet": r.text[:500]})
        except Exception as e:
            print(f"Pastebin content fetch error for {u}: {str(e)}")
    return results

def try_s3_bucket_guess(domain):
    if not requests:
        return []
    
    candidates = [
        domain, domain.replace(".", "-"), f"www-{domain}", f"{domain}-assets", f"assets-{domain}"
    ]
    found = []
    headers = {"User-Agent": "ReconToolkit/1.0"}
    for c in candidates:
        urls = [f"https://{c}.s3.amazonaws.com", f"https://s3.amazonaws.com/{c}"]
        for u in urls:
            try:
                print(f"Checking S3 bucket at {u}")
                r = requests.get(u, timeout=6, headers=headers, allow_redirects=True)
                if r.status_code in (200, 403):
                    found.append({"bucket": c, "url": u, "status": r.status_code})
            except Exception as e:
                print(f"S3 bucket check error for {u}: {str(e)}")
    return found

def cve_search(query_software):
    if not requests:
        return []
    
    out = []
    try:
        url = f"https://cve.circl.lu/api/search/{requests.utils.quote(query_software)}"
        print(f"Querying CVE for {query_software}")
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            for c in data.get("results", [])[:20]:
                out.append({"id": c.get("id"), "summary": c.get("summary"),
                            "cvss": c.get("cvss"), "references": c.get("references")})
    except Exception as e:
        print(f"CVE search error for {query_software}: {str(e)}")
    return out

def shodan_lookup_ip(ip):
    if not SHODAN_API_KEY or not shodan:
        return {"error": "Shodan not configured or library missing"}
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        print(f"Querying Shodan for {ip}")
        res = api.host(ip)
        return res
    except Exception as e:
        print(f"Shodan lookup error for {ip}: {str(e)}")
        return {"error": str(e)}

def parse_shodan_cves(ip, shodan_data):
    """Extract CVE entries from a Shodan host lookup response.
    Returns a list of normalized CVE dicts: {id, cvss?, summary, references[]}.
    """
    try:
        if not isinstance(shodan_data, dict):
            return []

        items = []

        def add_item(cve_id, cvss=None, port=None, product=None, version=None, scope="host"):
            entry = {"id": str(cve_id).upper()}
            if cvss is not None:
                try:
                    entry["cvss"] = float(cvss)
                except Exception:
                    entry["cvss"] = cvss
            parts = []
            if product:
                parts.append(str(product))
            if version:
                parts.append(str(version))
            loc = ip if port is None else f"{ip}:{port}"
            scope_txt = "service" if port is not None else scope
            summary = " ".join(parts).strip() or "Vulnerability reported by Shodan"
            entry["summary"] = f"{summary} on {loc} ({scope_txt})"
            entry["references"] = [f"https://nvd.nist.gov/vuln/detail/{entry['id']}"]
            items.append(entry)

        # Host-level CVEs (top-level 'vulns')
        host_vulns = shodan_data.get("vulns") or shodan_data.get("vulnerabilities")
        if isinstance(host_vulns, dict):
            for cve_id, meta in host_vulns.items():
                cvss_val = None
                if isinstance(meta, dict):
                    cvss_val = meta.get("cvss") or meta.get("cvssv3") or meta.get("cvssv2")
                add_item(cve_id, cvss=cvss_val)
        elif isinstance(host_vulns, list):
            for cve_id in host_vulns:
                add_item(cve_id)

        # Service-level CVEs (within each banner in 'data')
        for d in shodan_data.get("data", []) or []:
            d_vulns = d.get("vulns") or d.get("vulnerabilities")
            if not d_vulns:
                continue
            port = d.get("port")
            product = d.get("product")
            version = d.get("version")
            if not product and isinstance(d.get("http"), dict):
                product = d.get("http", {}).get("server")
            if isinstance(d_vulns, dict):
                for cve_id, meta in d_vulns.items():
                    cvss_val = meta.get("cvss") if isinstance(meta, dict) else None
                    add_item(cve_id, cvss=cvss_val, port=port, product=product, version=version, scope="service")
            elif isinstance(d_vulns, list):
                for cve_id in d_vulns:
                    add_item(cve_id, port=port, product=product, version=version, scope="service")

        # Deduplicate by (id, summary)
        unique = []
        seen = set()
        for it in items:
            key = (it.get("id"), it.get("summary"))
            if key not in seen:
                seen.add(key)
                unique.append(it)
        return unique
    except Exception:
        return []

def run_harvester_subprocess(domain, limit=200):
    """Run theHarvester via subprocess"""
    emails = set()
    hostnames = set()
    
    theharvester_dir = os.path.join(os.path.dirname(__file__), "theHarvester")
    commands = [
        [sys.executable, "-m", "theHarvester", "-d", domain, "-l", str(limit), "-b", "bing"],
        [sys.executable, "-m", "theHarvester", "-d", domain, "-l", str(limit), "-b", "yahoo"],
        [sys.executable, "-m", "theHarvester", "-d", domain, "-l", str(limit), "-b", "duckduckgo"],
        ["theHarvester", "-d", domain, "-l", str(limit), "-b", "bing"],
        ["theHarvester", "-d", domain, "-l", str(limit), "-b", "yahoo"]
    ]
    
    for cmd in commands:
        try:
            print(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, cwd=theharvester_dir, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                output = (result.stdout or "") + "\n" + (result.stderr or "")
                # Parse emails
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                found_emails = re.findall(email_pattern, output)
                emails.update(found_emails)
                
                # Parse hostnames
                lines = output.split('\n')
                for line in lines:
                    if domain in line and '.' in line:
                        words = line.split()
                        for word in words:
                            if word.endswith(domain) and word.count('.') >= 1:
                                hostnames.add(word.strip('.,;:'))
                break  # Success, don't try other commands
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
        except Exception as e:
            print(f"theHarvester error: {e}")
            continue
    
    return {"emails": list(emails), "hosts": list(hostnames)}

def get_typosquats_subprocess(domain):
    """Run dnstwist via subprocess"""
    try:
        print(f"Running dnstwist subprocess for {domain}")
        result = subprocess.run(['dnstwist', '--format', 'json', domain], 
                              capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            registered = [d['domain'] for d in data[1:] if d.get('dns_a') or d.get('dns_aaaa')]
            return registered
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError) as e:
        print(f"dnstwist command error for {domain}: {str(e)}")
    except Exception as e:
        print(f"dnstwist subprocess error for {domain}: {str(e)}")
    return []

def get_mx_records(domain):
    mx = []
    if dns_resolver:
        try:
            resolver = dns_resolver.Resolver()
            print(f"Querying MX records for {domain}")
            answers = resolver.resolve(domain, 'MX')
            for r in answers:
                mx.append(str(r.exchange).rstrip('.'))
        except Exception as e:
            print(f"MX record lookup failed for {domain}: {str(e)}")
    else:
        # Fallback to dig
        try:
            result = subprocess.run(['dig', '+short', domain, 'MX'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    parts = line.strip().split()
                    if parts and len(parts) > 1:
                        mx_record = parts[1].rstrip('.')
                        if mx_record:
                            mx.append(mx_record)
        except FileNotFoundError:
            print(f"dig command not available for MX lookup: {domain}")
        except Exception as e:
            print(f"MX subprocess failed for {domain}: {e}")
    return mx

def run_sublist3r_subprocess(domain):
    """Run Sublist3r via subprocess"""
    subdomains = []
    commands = [
        ["python3", "-m", "sublist3r", "-d", domain, "-v"],
        ["sublist3r", "-d", domain, "-v"],
        ["python", "-m", "sublist3r", "-d", domain, "-v"]
    ]
    
    for cmd in commands:
        try:
            print(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                output_lines = result.stdout.split('\n')
                for line in output_lines:
                    line = line.strip()
                    if line.endswith(domain) and line not in subdomains:
                        subdomains.append(line)
                break
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
        except Exception as e:
            print(f"Sublist3r error: {e}")
            continue
    
    return subdomains

def map_services_to_sf_modules(services):
    """Map user service selections to SpiderFoot modules"""
    mapping = {
        "domainSubdomain": ["sfp_dnsresolve", "sfp_crt", "sfp_certspotter", "sfp_dnsbrute"],
        "techFingerprint": ["sfp_builtwith", "sfp_whatcms", "sfp_webanalytics", "sfp_webframework"],
        "portScan": ["sfp_portscan_tcp", "sfp_shodan", "sfp_censys"],
        "employeeData": ["sfp_hunter", "sfp_emailformat", "sfp_github", "sfp_names"],
        "cloudExposure": ["sfp_azureblobstorage", "sfp_s3bucket", "sfp_digitaloceanspace"],
        "cveMapping": ["sfp_cve", "sfp_vulndb", "sfp_xforce"]
    }
    
    modules = []
    for service, enabled in services.items():
        if enabled and service in mapping:
            modules.extend(mapping[service])
    
    # Remove duplicates while preserving order
    seen = set()
    unique_modules = []
    for module in modules:
        if module not in seen:
            seen.add(module)
            unique_modules.append(module)
    
    return unique_modules

def extract_all_ips(results):
    """Extract all unique IPs from scan results"""
    ips = set()
    
    # Extract from hosts
    for host in results.get("hosts", []):
        for ip in host.get("ips", []):
            ips.add(ip)
    
    # Extract from IP ranges if available
    for ip_range in results.get("ip_ranges", []):
        ips.add(ip_range)
    
    return list(ips)

def extract_all_ports(results):
    """Extract all discovered ports from scan results"""
    ports = set()
    
    for host in results.get("hosts", []):
        for port in host.get("open_ports", []):
            ports.add(port)
    
    return list(ports)

def run_spiderfoot_with_injection(domain, modules, seed_data):
    """Run SpiderFoot with selective modules and injected seed data"""
    try:
        # Create temporary file with seed data for SpiderFoot
        import tempfile
        seed_file = None
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(seed_data, f)
            seed_file = f.name
        
        # Build SpiderFoot command with selective modules
        spiderfoot_dir = os.path.join(os.path.dirname(__file__), "spiderfoot")
        if not os.path.isdir(spiderfoot_dir):
            return {"status": "failed", "error": f"SpiderFoot directory not found"}
        
        # Join modules with comma
        modules_str = ",".join(modules) if modules else "sfp_dnsresolve"
        
        cmd = [
            sys.executable, 
            "sf.py", 
            "-t", domain,
            "-m", modules_str,
            "-s", domain,
            "-q"  # Quiet mode
        ]
        
        print(f"Running selective SpiderFoot: {' '.join(cmd)}")
        print(f"Using modules: {modules_str}")
        print(f"Seed data: {len(seed_data.get('subdomains', []))} subdomains, {len(seed_data.get('ips', []))} IPs")
        
        result = subprocess.run(
            cmd, 
            cwd=spiderfoot_dir, 
            capture_output=True, 
            text=True, 
            timeout=180  # 3 minute timeout for enhancement
        )
        
        # Parse SpiderFoot output
        output_lines = result.stdout.split('\n') if result.stdout else []
        events = []
        
        for line in output_lines:
            if line.strip():
                # Basic parsing - can be enhanced based on SpiderFoot output format
                events.append(line.strip())
        
        # Clean up seed file
        if seed_file and os.path.exists(seed_file):
            os.remove(seed_file)
        
        return {
            "status": "success",
            "modules_run": modules,
            "events_found": len(events),
            "events": events[:100],  # Limit to first 100 events
            "seed_data_used": {
                "subdomains": len(seed_data.get("subdomains", [])),
                "ips": len(seed_data.get("ips", [])),
                "emails": len(seed_data.get("emails", []))
            }
        }
        
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "error": "SpiderFoot enhancement timed out after 3 minutes"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def run_spiderfoot_subprocess(domain, output_dir, timeout_seconds=300):
    """Run SpiderFoot via subprocess"""
    try:
        # Ensure we execute the bundled SpiderFoot located under backend/spiderfoot
        spiderfoot_dir = os.path.join(os.path.dirname(__file__), "spiderfoot")
        if not os.path.isdir(spiderfoot_dir):
            return {"status": "failed", "error": f"SpiderFoot directory not found at {spiderfoot_dir}"}

        spiderfoot_commands = [
            [sys.executable, "sf.py", "-t", domain, "-m", "sfp_dnsresolve,sfp_crt,sfp_builtwith", "-s", domain],
            ["python", "sf.py", "-t", domain, "-m", "sfp_dnsresolve,sfp_crt,sfp_builtwith", "-s", domain],
            ["python3", "sf.py", "-t", domain, "-m", "sfp_dnsresolve,sfp_crt,sfp_builtwith", "-s", domain]
        ]

        for cmd in spiderfoot_commands:
            try:
                print(f"Running SpiderFoot: {' '.join(cmd)} (cwd={spiderfoot_dir})")
                result = subprocess.run(cmd, cwd=spiderfoot_dir, capture_output=True, text=True, timeout=timeout_seconds)
                if result.returncode == 0:
                    return {"status": "success", "output": result.stdout[:2000]}
            except subprocess.TimeoutExpired:
                return {"status": "timeout", "error": f"SpiderFoot timed out after {timeout_seconds}s"}
            except FileNotFoundError:
                continue

        return {"status": "failed", "error": "SpiderFoot not available or failed"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

# -------------------------
# Scan configuration for different recon types
# -------------------------
def get_scan_config(recon_type, services):
    """Configure scan parameters based on recon type and selected services"""
    
    # Base configuration
    config = {
        "enable_whois": True,
        "enable_subdomains": services.get("domainSubdomain", True),
        "enable_tech_detection": services.get("techFingerprint", True),
        "enable_port_scan": services.get("portScan", True),
        "enable_osint": services.get("employeeData", False),
        "enable_cloud_enum": services.get("cloudExposure", False),
        "enable_cve_mapping": services.get("cveMapping", False),
        "subdomain_threads": 10,
        "port_timeout": 2.0,
        "max_subdomains": 50,
        "enable_bruteforce": True,
        "enable_crt_sh": True,
        "enable_sublist3r": True
    }
    
    if recon_type == "quick":
        # Quick scan: minimal modules, fast execution
        config.update({
            "subdomain_threads": 5,
            "port_timeout": 1.0,
            "max_subdomains": 20,
            "enable_bruteforce": False,
            "enable_crt_sh": True,
            "enable_sublist3r": False,
            "ports_to_scan": [80, 443, 22, 21, 25],
            "enable_harvester": False,
            "enable_github_search": False,
            "enable_pastebin_search": False,
            "enable_shodan": True,
            # Force-disable OSINT for quick scans regardless of UI toggles
            "enable_osint": False,
            # Hard caps to keep quick scans fast on large domains
            "max_hosts_for_ports": 12,
            # Keep Shodan lookups minimal
            "shodan_ip_limit": 5
        })
        
    elif recon_type == "normal":
        # Normal scan: balanced approach
        config.update({
            "subdomain_threads": 15,
            "port_timeout": 2.0,
            "max_subdomains": 100,
            "enable_bruteforce": True,
            "enable_crt_sh": True,
            "enable_sublist3r": True,
            "ports_to_scan": TOP_PORTS,
            "enable_harvester": services.get("employeeData", False),
            "enable_github_search": services.get("employeeData", False),
            "enable_pastebin_search": services.get("employeeData", False),
            "enable_shodan": True,
            # Sensible limits for medium scans
            "max_hosts_for_ports": 60,
            "shodan_ip_limit": 15
        })
        
    elif recon_type == "deep":
        # Deep scan: comprehensive analysis
        config.update({
            "subdomain_threads": 25,
            "port_timeout": 3.0,
            "max_subdomains": 500,
            "enable_bruteforce": True,
            "enable_crt_sh": True,
            "enable_sublist3r": True,
            "ports_to_scan": TOP_PORTS + [1723, 5432, 3306, 1433, 5984, 6379, 27017],
            "enable_harvester": True,
            "enable_github_search": True,
            "enable_pastebin_search": True,
            "enable_typosquatting": True,
            "enable_shodan": True,
            # Larger limits for deep scans
            "max_hosts_for_ports": 150,
            "shodan_ip_limit": 30
        })
    
    return config

# -------------------------
# Recon worker with different scan types
# -------------------------
def run_recon(target, options=None, job_id=None):
    domain = normalized_domain(target)
    recon_type = options.get("recon_type", "quick") if options else "quick"
    services = options.get("services", {}) if options else {}
    
    print(f"Starting {recon_type} recon for {domain}")
    
    # Check if job was cancelled before starting
    if job_id and job_id in CANCELLED_JOBS:
        return {"error": "Job was cancelled", "cancelled": True}
    
    start_time = datetime.now(timezone.utc)
    result = {
        "target": domain,
        "timestamp": start_time.isoformat() + "Z",
        "start_time": start_time.isoformat() + "Z",
        "recon_type": recon_type,
        "services_used": services,
        "subdomains": [],
        "hosts": [],
        "whois": {},
        "tech": {},
        "github_hits": [],
        "paste_hits": [],
        "s3_buckets": [],
        "typosquats": [],
        "cves": {},
        "shodan": {},
        "phishing_vectors": {},
        "spiderfoot_events": [],
        "harvester": {"emails": [], "hosts": []},
        "status": "running",
        "cancelled": False
    }
    
    # Configure scan parameters based on recon type
    scan_config = get_scan_config(recon_type, services)
    
    # Add timeout limits based on scan type
    max_duration = {
        "quick": 180,    # 3 minutes
        "normal": 450,   # 7.5 minutes  
        "deep": 900     # 15 minutes
    }.get(recon_type, 900)
    
    def check_cancelled():
        return job_id and job_id in CANCELLED_JOBS
    
    def check_timeout():
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        return elapsed > max_duration
    
    # WHOIS lookup
    if scan_config.get("enable_whois", True):
        if check_cancelled():
            result["cancelled"] = True
            return result
        result["whois"] = whois_lookup(domain)
        # Merge WHOIS emails into email intelligence results for UI display
        try:
            we = result["whois"].get("emails") if isinstance(result.get("whois"), dict) else None
            emails_from_whois = []
            if we:
                if isinstance(we, (list, set, tuple)):
                    emails_from_whois = [str(e) for e in we if e]
                else:
                    emails_from_whois = [str(we)]
            if emails_from_whois:
                existing = set(result.get("harvester", {}).get("emails", []))
                merged = sorted(existing.union(emails_from_whois))
                result["harvester"]["emails"] = merged
        except Exception as e:
            print(f"WHOIS email merge failed: {e}")
    
    # IP ranges from WHOIS
    if scan_config.get("enable_whois", True):
        w = result["whois"]
        if "nets" in w and w["nets"]:
            result["ip_ranges"] = [net.get("cidr") for net in w["nets"] if net.get("cidr")]
        elif "cidr" in w:
            result["ip_ranges"] = [w["cidr"]]

    # Subdomain enumeration
    if scan_config.get("enable_subdomains", True):
        if check_cancelled() or check_timeout():
            result["cancelled"] = check_cancelled()
            result["timeout"] = check_timeout()
            return result
        print(f"Running subdomain enumeration for {domain}")
        wl = options.get("wordlist") if options else DEFAULT_WORDS
        if isinstance(wl, str) and os.path.exists(wl):
            with open(wl, "r") as f:
                wl = [l.strip() for l in f if l.strip()]
        elif not isinstance(wl, list):
            wl = DEFAULT_WORDS

        # 1. Sublist3r subprocess
        if scan_config.get("enable_sublist3r", False):
            if check_cancelled() or check_timeout():
                result["cancelled"] = check_cancelled()
                result["timeout"] = check_timeout()
                return result
            try:
                sublist3r_subs = run_sublist3r_subprocess(domain)
                result["subdomains"].extend(sublist3r_subs[:scan_config.get("max_subdomains", 50)])
            except Exception as e:
                print(f"Sublist3r subprocess error: {e}")

        # 2. CRT.sh lookup (if enabled)
        if scan_config.get("enable_crt_sh", True):
            try:
                crt_subs = crt_sh_subdomains(domain)
                for sub in crt_subs[:scan_config.get("max_subdomains", 50)]:
                    if sub not in result["subdomains"]:
                        result["subdomains"].append(sub)
            except Exception as e:
                print(f"CRT.sh error: {e}")

        # DNS bruteforce
        if scan_config.get("enable_bruteforce", False):
            if check_cancelled() or check_timeout():
                result["cancelled"] = check_cancelled()
                result["timeout"] = check_timeout()
                return result
            bruteforce_results = dns_bruteforce(domain, threads=scan_config.get("subdomain_threads", 10))
            for subdomain, ips in bruteforce_results:
                if subdomain not in result["subdomains"]:
                    result["subdomains"].append(subdomain)

        # 4. theHarvester subprocess moved to independent OSINT stage below

        # Note: Removed duplicate CRT.sh fetch to prevent unbounded subdomain growth

        # Fallback if no subdomains found
        if not result["subdomains"]:
            fallback_subs = crt_sh_subdomains(domain)
            result["subdomains"].extend(fallback_subs[:10])  # Limit fallback

        # Enforce a global subdomain cap and deduplicate across sources
        result["subdomains"] = sorted(set(result["subdomains"]))[:scan_config.get("max_subdomains", 50)]

    # Email harvesting (theHarvester) - independent of subdomain enumeration
    if scan_config.get("enable_harvester", False):
        if check_cancelled() or check_timeout():
            result["cancelled"] = check_cancelled()
            result["timeout"] = check_timeout()
            return result
        try:
            hv = run_harvester_subprocess(domain)
            if isinstance(hv, dict):
                result["harvester"] = hv
            else:
                result["harvester"] = {"emails": [], "hosts": []}
            # Only merge hosts into subdomains when subdomain enumeration is enabled
            if scan_config.get("enable_subdomains", False) and "hosts" in result["harvester"]:
                for h in result["harvester"]["hosts"]:
                    if h.endswith(domain) and h not in result["subdomains"]:
                        result["subdomains"].append(h)
                # Deduplicate and cap after merging
                result["subdomains"] = sorted(set(result["subdomains"]))[:scan_config.get("max_subdomains", 50)]
        except Exception as e:
            print(f"theHarvester error: {e}")
            result["harvester"] = {"error": str(e), "emails": [], "hosts": []}

    # Resolve subdomains & scan ports
    hosts_map = {}
    subdomains = set(result["subdomains"])
    subdomains.add(domain)

    # Apply host scan limit (especially important for quick scans)
    all_hosts = [domain] + [s for s in sorted(subdomains) if s != domain]
    max_hosts = scan_config.get("max_hosts_for_ports", len(all_hosts))
    all_hosts = all_hosts[:max_hosts]

    # DNS resolution
    for sub in all_hosts:
        ips = dns_resolve(sub)
        hosts_map[sub] = {"hostname": sub, "ips": ips, "open_ports": [], "services": []}

    # Port scanning (if enabled)
    if scan_config.get("enable_port_scan", True):
        ports_to_scan = scan_config.get("ports_to_scan", TOP_PORTS)
        port_timeout = scan_config.get("port_timeout", 2.0)
        
        for host, data in hosts_map.items():
            if check_cancelled() or check_timeout():
                result["cancelled"] = check_cancelled()
                result["timeout"] = check_timeout()
                return result
            for ip in data["ips"]:
                if check_cancelled() or check_timeout():
                    result["cancelled"] = check_cancelled()
                    result["timeout"] = check_timeout()
                    return result
                print(f"Scanning ports for {ip} (timeout: {port_timeout}s)")
                open_ports, services = simple_port_scan(ip, ports=ports_to_scan, timeout=port_timeout)
                data["open_ports"].extend(open_ports)
                data["open_ports"] = list(set(data["open_ports"]))
                data["services"].extend([f"{s['port']}:{s['banner']}" for s in services])

    result["hosts"] = list(hosts_map.values())

    # Technology detection
    if scan_config.get("enable_tech_detection", True):
        if check_cancelled() or check_timeout():
            result["cancelled"] = check_cancelled()
            result["timeout"] = check_timeout()
            return result
        tech_urls = [f"https://{domain}", f"http://{domain}"]
        for url in tech_urls:
            try:
                tech_data = detect_techstack_from_url(url)
                if tech_data:
                    result["tech"][url] = tech_data
                    break
            except Exception as e:
                print(f"Tech detection error for {url}: {str(e)}")

    # OSINT and public sources (if enabled)
    if scan_config.get("enable_osint", False):
        if scan_config.get("enable_github_search", False):
            result["github_hits"] = github_search_code(domain, token=GITHUB_TOKEN)
        
        if scan_config.get("enable_pastebin_search", False):
            result["paste_hits"] = pastebin_search(domain)

    
    # Cloud enumeration (if enabled)
    if scan_config.get("enable_cloud_enum", False):
        result["s3_buckets"] = try_s3_bucket_guess(domain)

    # CVE mapping (if enabled)
    if scan_config.get("enable_cve_mapping", False) and result.get("tech"):
        software_names = list(result["tech"].keys())
        for s in software_names[:8]:
            cves = cve_search(s)
            if cves:
                result["cves"][s] = cves

    # Shodan lookup (if enabled and configured)
    if scan_config.get("enable_shodan", False) and SHODAN_API_KEY and shodan:
        ips = set(ip for h in result["hosts"] for ip in h.get("ips", []))
        max_shodan_ips = scan_config.get("shodan_ip_limit", 15)
        for ip in list(ips)[:max_shodan_ips]:
            result["shodan"][ip] = shodan_lookup_ip(ip)

        # Extract CVEs from Shodan results and expose under Vulnerabilities
        shodan_cves = []
        for ip, shodan_res in result.get("shodan", {}).items():
            shodan_cves.extend(parse_shodan_cves(ip, shodan_res))

        if shodan_cves:
            result.setdefault("cves", {})
            if not isinstance(result["cves"].get("Shodan"), list):
                result["cves"]["Shodan"] = []

            existing = set((c.get("id"), c.get("summary", "")) for c in result["cves"]["Shodan"])
            for c in shodan_cves:
                key = (c.get("id"), c.get("summary", ""))
                if key not in existing:
                    result["cves"]["Shodan"].append(c)
                    existing.add(key)

    # Phishing vectors (for deep scans)
    if recon_type == "deep" or scan_config.get("enable_typosquatting", False):
        result["phishing_vectors"]["mx_servers"] = get_mx_records(domain)
        result["phishing_vectors"]["typosquat_domains"] = get_typosquats_subprocess(domain)

    # SpiderFoot Integration
    if options and options.get("use_spiderfoot"):
        try:
            safe_domain = re.sub(r"[^A-Za-z0-9_.-]", "_", domain)
            sf_output_dir = os.path.join(OUTPUT_DIR, safe_domain)
            os.makedirs(sf_output_dir, exist_ok=True)
            # Apply a strict timeout for SpiderFoot based on recon type to keep quick scans fast
            sf_timeout = {
                "quick": 45,   # 45 seconds max for quick scans
                "normal": 180, # 3 minutes
                "deep": 300    # 5 minutes
            }.get(recon_type, 120)
            spiderfoot_result = run_spiderfoot_subprocess(domain, sf_output_dir, timeout_seconds=sf_timeout)
            result["spiderfoot_events"].append(spiderfoot_result)
        except Exception as e:
            result["spiderfoot_events"].append({"error": str(e)})

    # Save output
    json_path, csv_path = save_output(domain, result)
    result["output_files"] = {"json": json_path, "csv": csv_path}

    # Update summary with spiderfoot status
    spiderfoot_status = "not_run"
    if result["spiderfoot_events"] and isinstance(result["spiderfoot_events"], list) and result["spiderfoot_events"]:
        first_event = result["spiderfoot_events"][0]
        if isinstance(first_event, dict) and "status" in first_event:
            spiderfoot_status = first_event["status"]

    result["summary"] = {
        "num_subdomains": len(result["subdomains"]),
        "num_hosts": len(result["hosts"]),
        "num_emails": len(result["harvester"].get("emails", [])),
        "github_hits": len(result["github_hits"]),
        "paste_hits": len(result["paste_hits"]),
        "spiderfoot_status": spiderfoot_status
    }
    
    # Save partial results even if cancelled/timeout
    try:
        json_path, csv_path = save_output(domain, result)
        result["output_files"] = {"json": json_path, "csv": csv_path}
    except Exception as e:
        print(f"Failed to save output: {e}")
        result["save_error"] = str(e)

    # Calculate final duration and status
    end_time = datetime.now(timezone.utc)
    result["end_time"] = end_time.isoformat() + "Z"
    result["duration_seconds"] = int((end_time - start_time).total_seconds())
    result["duration_formatted"] = format_duration(result["duration_seconds"])
    
    if result.get("cancelled"):
        result["status"] = "cancelled"
        print(f"Recon cancelled for {domain} after {result['duration_formatted']}")
    elif result.get("timeout"):
        result["status"] = "timeout"
        print(f"Recon timed out for {domain} after {result['duration_formatted']}")
    else:
        result["status"] = "completed"
        print(f"Recon completed for {domain} in {result['duration_formatted']}")
    
    return result

# -------------------------
# Flask endpoints
# -------------------------
JOBS = {}
CANCELLED_JOBS = set()  # Track cancelled jobs
JOB_THREADS = {}  # Track running threads

@app.route("/api/recon", methods=["GET", "POST"])
def api_recon():
    ok, msg = require_authorization(request)
    if not ok:
        return jsonify({"error": msg}), 403

    # Handle both GET and POST requests
    if request.method == "POST":
        data = request.get_json() or {}
        target = data.get("target")
        recon_type = data.get("reconType", "quick")
        services = data.get("services", {})
        wordlist = data.get("customWordlist")
        use_sf = data.get("useSpiderfoot", False)
    else:
        target = request.args.get("target")
        recon_type = request.args.get("recon_type", "quick")
        services = {}
        wordlist = request.args.get("wordlist")
        use_sf = request.args.get("use_spiderfoot") == "1"

    if not target:
        return jsonify({"error": "Missing required parameter: target"}), 400

    # Build options based on reconnaissance type and selected services
    options = {
        "recon_type": recon_type,
        "services": services,
        "use_spiderfoot": use_sf
    }
    if wordlist:
        options["wordlist"] = wordlist

    job_id = str(int(time.time() * 1000))
    start_time = datetime.now(timezone.utc)
    JOBS[job_id] = {
        "status": "running", 
        "target": target, 
        "recon_type": recon_type, 
        "started": start_time.isoformat(),
        "start_time": start_time.isoformat(),
        "services": services
    }

    def run_recon_thread():
        try:
            res = run_recon(target, options=options, job_id=job_id)
            end_time = datetime.now(timezone.utc)
            JOBS[job_id].update({
                "status": res.get("status", "finished"),
                "finished": end_time.isoformat(),
                "end_time": end_time.isoformat(),
                "result": res,
                "duration_seconds": int((end_time - start_time).total_seconds()),
                "duration_formatted": format_duration(int((end_time - start_time).total_seconds()))
            })
            if job_id in JOB_THREADS:
                del JOB_THREADS[job_id]
        except Exception as e:
            end_time = datetime.now(timezone.utc)
            JOBS[job_id].update({
                "status": "error", 
                "error": str(e),
                "finished": end_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration_seconds": int((end_time - start_time).total_seconds()),
                "duration_formatted": format_duration(int((end_time - start_time).total_seconds()))
            })
            print(f"Recon error for {target}: {str(e)}")
            traceback.print_exc()
            if job_id in JOB_THREADS:
                del JOB_THREADS[job_id]
    
    # Start reconnaissance in background thread
    thread = threading.Thread(target=run_recon_thread, daemon=True)
    thread.start()
    JOB_THREADS[job_id] = thread
    
    return jsonify({"success": True, "data": {"job_id": job_id, "status": "started"}})

@app.route("/api/status/<job_id>", methods=["GET"])
def api_status(job_id):
    ok, msg = require_authorization(request)
    if not ok:
        return jsonify({"error": msg}), 403
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "unknown job id"}), 404
    
    # Add current duration for running jobs
    if job["status"] == "running" and "start_time" in job:
        start_time = datetime.fromisoformat(job["start_time"].replace('Z', '+00:00'))
        current_time = datetime.now(timezone.utc)
        job["current_duration_seconds"] = int((current_time - start_time).total_seconds())
        job["current_duration_formatted"] = format_duration(job["current_duration_seconds"])
    
    return jsonify(job)

@app.route("/api/stop/<job_id>", methods=["POST"])
def api_stop_scan(job_id):
    """Stop a running scan and return partial results"""
    ok, msg = require_authorization(request)
    if not ok:
        return jsonify({"error": msg}), 403
    
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "unknown job id"}), 404
    
    if job["status"] != "running":
        return jsonify({"error": "job is not running"}), 400
    
    # Mark job as cancelled
    CANCELLED_JOBS.add(job_id)
    
    # Wait a short time for graceful shutdown
    if job_id in JOB_THREADS:
        thread = JOB_THREADS[job_id]
        thread.join(timeout=2.0)  # Wait up to 2 seconds
    
    return jsonify({"success": True, "message": "Scan stop requested"})

@app.route("/api/enhance/<job_id>", methods=["POST"])
def api_enhance_with_spiderfoot(job_id):
    """Enhance existing scan results with selective SpiderFoot modules"""
    ok, msg = require_authorization(request)
    if not ok:
        return jsonify({"error": msg}), 403
    
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "unknown job id"}), 404
    
    if "result" not in job:
        return jsonify({"error": "No results to enhance"}), 400
    
    data = request.get_json() or {}
    services = data.get("services", {})
    
    original_results = job["result"]
    domain = original_results["target"]
    
    # Map services to SpiderFoot modules
    sf_modules = map_services_to_sf_modules(services)
    
    if not sf_modules:
        return jsonify({"error": "No SpiderFoot modules selected"}), 400
    
    # Extract data from original results for injection
    injection_data = {
        "subdomains": original_results.get("subdomains", []),
        "ips": extract_all_ips(original_results),
        "emails": original_results.get("harvester", {}).get("emails", []),
        "ports": extract_all_ports(original_results),
        "technologies": list(original_results.get("tech", {}).keys())
    }
    
    # Run SpiderFoot with selective modules and injected data
    try:
        enhanced_results = run_spiderfoot_with_injection(
            domain=domain,
            modules=sf_modules,
            seed_data=injection_data
        )
        
        # Store enhanced results
        job["enhanced_results"] = enhanced_results
        job["enhancement_timestamp"] = datetime.now(timezone.utc).isoformat()
        
        return jsonify({
            "success": True,
            "modules_used": sf_modules,
            "data_injected": {
                "subdomains": len(injection_data["subdomains"]),
                "ips": len(injection_data["ips"]),
                "emails": len(injection_data["emails"]),
                "technologies": len(injection_data["technologies"])
            },
            "results": enhanced_results
        })
        
    except Exception as e:
        return jsonify({"error": f"Enhancement failed: {str(e)}"}), 500

@app.route("/api/jobs", methods=["GET"])
def api_list_jobs():
    """List all jobs with their status"""
    ok, msg = require_authorization(request)
    if not ok:
        return jsonify({"error": msg}), 403
    
    jobs_summary = {}
    for job_id, job_data in JOBS.items():
        jobs_summary[job_id] = {
            "status": job_data["status"],
            "target": job_data["target"],
            "recon_type": job_data["recon_type"],
            "started": job_data["started"],
            "duration_formatted": job_data.get("duration_formatted", "N/A")
        }
    
    return jsonify({"jobs": jobs_summary, "cancelled_count": len(CANCELLED_JOBS)})

@app.route("/api/health", methods=["GET"])
def api_health():
    """Health check endpoint"""
    status = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dependencies": {
            "requests": requests is not None,
            "whois": whois_module is not None,
            "dns_resolver": dns_resolver is not None,
            "builtwith": builtwith is not None,
            "shodan": shodan is not None,
            "sublist3r": sublist3r is not None
        },
        "config": {
            "shodan_configured": bool(SHODAN_API_KEY),
            "github_configured": bool(GITHUB_TOKEN),
            "censys_configured": bool(CENSYS_ID and CENSYS_SECRET),
            "auth_configured": bool(AUTHORIZATION_KEY)
        },
        "tools_status": {
            "subprocess_available": True,
            "socket_available": True,
            "dns_fallback": True,
            "whois_fallback": True
        }
    }
    return jsonify(status)

@app.route("/api/tools/test", methods=["GET"])
def api_test_tools():
    """Test individual tools availability"""
    ok, msg = require_authorization(request)
    if not ok:
        return jsonify({"error": msg}), 403
    
    test_results = {}
    
    # Test subprocess tools
    subprocess_tools = ["whois", "dnstwist", "sublist3r", "theHarvester", "dig"]
    for tool in subprocess_tools:
        try:
            result = subprocess.run([tool, "--help"], capture_output=True, timeout=5)
            test_results[tool] = {"available": result.returncode == 0, "method": "subprocess"}
        except (FileNotFoundError, subprocess.TimeoutExpired):
            test_results[tool] = {"available": False, "method": "subprocess"}
        except Exception as e:
            test_results[tool] = {"available": False, "method": "subprocess", "error": str(e)}
    
    # Test Python modules
    python_modules = {
        "requests": requests,
        "whois": whois_module,
        "dns.resolver": dns_resolver,
        "builtwith": builtwith,
        "shodan": shodan,
        "sublist3r": sublist3r
    }
    
    for module_name, module_obj in python_modules.items():
        test_results[f"python_{module_name}"] = {
            "available": module_obj is not None,
            "method": "python_import"
        }
    
    return jsonify({"test_results": test_results})

@app.route("/api/export/pdf", methods=["POST"])
def api_export_pdf():
    """Server-side PDF export using ReportLab"""
    ok, msg = require_authorization(request)
    if not ok:
        return jsonify({"error": msg}), 403
    if render_report_pdf is None:
        return jsonify({"error": "PDF export unavailable on server"}), 503
    try:
        payload = request.get_json() or {}
        results = payload.get("results") or {}
        target = payload.get("target") or results.get("target") or "target"
        sf_enhanced = payload.get("sf_enhanced")

        pdf_bytes = render_report_pdf(results, target, sf_enhanced)
        buf = BytesIO(pdf_bytes)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", str(target))
        ts = datetime.now(timezone.utc).isoformat().replace(":", "-").replace(".", "-")
        filename = f"{safe}_recon_{ts}.pdf"
        return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({"error": f"Failed to export PDF: {str(e)}"}), 500

@app.route("/")
def index():
    return (
        "<h3>Recon Toolkit Backend (Subprocess-Enhanced)</h3>"
        "<p>Use <code>/api/recon?target=example.com&auth=YOUR_KEY&use_spiderfoot=1</code> to start recon.</p>"
        "<p>Check <code>/api/health</code> for dependency status.</p>"
        "<p>Check <code>/api/tools/test</code> for individual tool testing.</p>"
        "<p><strong>Warning:</strong> Only use against authorized targets.</p>"
        "<h4>Available Endpoints:</h4>"
        "<ul>"
        "<li><code>GET /api/recon?target=DOMAIN&auth=KEY</code> - Start reconnaissance</li>"
        "<li><code>GET /api/status/JOB_ID?auth=KEY</code> - Check job status</li>"
        "<li><code>GET /api/health</code> - Check system health</li>"
        "<li><code>GET /api/tools/test?auth=KEY</code> - Test individual tools</li>"
        "</ul>"
        "<h4>Features:</h4>"
        "<ul>"
        "<li>Minimal import dependencies</li>"
        "<li>Subprocess fallbacks for all tools</li>"
        "<li>Native socket-based port scanning</li>"
        "<li>DNS resolution with multiple fallbacks</li>"
        "<li>Works without Python security tool libraries</li>"
        "</ul>"
    )

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

# Additional utility functions for enhanced functionality
def run_nmap_subprocess(target, ports=None):
    """Run nmap via subprocess as alternative to socket scanning"""
    if ports is None:
        ports = TOP_PORTS
    
    try:
        port_range = ",".join(map(str, ports))
        cmd = ["nmap", "-sS", "-p", port_range, target]
        print(f"Running nmap: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            open_ports = []
            lines = result.stdout.split('\n')
            for line in lines:
                if '/tcp' in line and 'open' in line:
                    port = int(line.split('/')[0])
                    open_ports.append(port)
            return open_ports
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"nmap not available or timed out: {e}")
    except Exception as e:
        print(f"nmap error: {e}")
    
    return []

def run_amass_subprocess(domain):
    """Run Amass via subprocess for subdomain enumeration"""
    subdomains = []
    try:
        cmd = ["amass", "enum", "-d", domain]
        print(f"Running amass: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            subdomains = [line.strip() for line in lines if line.strip().endswith(domain)]
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"amass not available or timed out: {e}")
    except Exception as e:
        print(f"amass error: {e}")
    
    return subdomains

def run_gobuster_subprocess(domain, wordlist_path=None):
    """Run Gobuster via subprocess for directory enumeration"""
    if not wordlist_path:
        return []
    
    directories = []
    try:
        cmd = ["gobuster", "dir", "-u", f"https://{domain}", "-w", wordlist_path, "-q"]
        print(f"Running gobuster: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if line.startswith('/'):
                    directories.append(line.strip())
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"gobuster not available or timed out: {e}")
    except Exception as e:
        print(f"gobuster error: {e}")
    
    return directories

def check_ssl_certificate(domain):
    """Check SSL certificate information using openssl subprocess"""
    cert_info = {}
    try:
        cmd = ["openssl", "s_client", "-connect", f"{domain}:443", "-servername", domain]
        result = subprocess.run(cmd, input="\n", capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            output = result.stdout
            # Parse certificate information
            if "subject=" in output:
                subject_line = [line for line in output.split('\n') if line.strip().startswith('subject=')]
                if subject_line:
                    cert_info['subject'] = subject_line[0].replace('subject=', '').strip()
            
            if "issuer=" in output:
                issuer_line = [line for line in output.split('\n') if line.strip().startswith('issuer=')]
                if issuer_line:
                    cert_info['issuer'] = issuer_line[0].replace('issuer=', '').strip()
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"openssl not available or timed out: {e}")
        cert_info['error'] = str(e)
    except Exception as e:
        print(f"SSL check error: {e}")
        cert_info['error'] = str(e)
    
    return cert_info

# Enhanced recon function with additional subprocess tools
def enhanced_run_recon(target, options=None):
    """Enhanced recon function with additional tools"""
    result = run_recon(target, options)  # Run base recon first
    
    domain = normalized_domain(target)
    
    # Add enhanced features
    try:
        # SSL Certificate check
        result['ssl_info'] = check_ssl_certificate(domain)
        
        # Try Amass for additional subdomain enumeration
        amass_subs = run_amass_subprocess(domain)
        if amass_subs:
            result['amass_subdomains'] = amass_subs
            for sub in amass_subs:
                if sub not in result['subdomains']:
                    result['subdomains'].append(sub)
        
        # Enhanced port scanning with nmap if available
        for host_info in result['hosts']:
            for ip in host_info['ips']:
                nmap_ports = run_nmap_subprocess(ip)
                if nmap_ports:
                    host_info['nmap_ports'] = nmap_ports
                    # Merge with existing ports
                    all_ports = set(host_info['open_ports'] + nmap_ports)
                    host_info['open_ports'] = sorted(list(all_ports))
        
    except Exception as e:
        print(f"Enhanced recon features error: {e}")
        result['enhanced_features_error'] = str(e)
    
    return result

if __name__ == "__main__":
    print("🚀 Starting Recon Toolkit backend (Subprocess-Enhanced)")
    print(f"📁 Output directory: {OUTPUT_DIR}")
    print(f"🔑 Authorization required: {bool(AUTHORIZATION_KEY)}")
    print(f"🌐 Requests available: {requests is not None}")
    print(f"🔍 DNS resolver available: {dns_resolver is not None}")
    print(f"📊 Shodan configured: {bool(SHODAN_API_KEY)}")
    print(f"🐙 GitHub configured: {bool(GITHUB_TOKEN)}")
    print(f"🔍 Censys configured: {bool(CENSYS_ID and CENSYS_SECRET)}")
    print("🛠️ Using subprocess fallbacks for external tools")
    print("⚠️ This version minimizes import dependencies and relies on system tools")
    
    # Test critical system tools on startup
    critical_tools = ["ping"]  # Removed nslookup from critical tools
    for tool in critical_tools:
        try:
            subprocess.run([tool, "--help"], capture_output=True, timeout=2)
            print(f"✅ {tool} available")
        except:
            print(f"❌ {tool} not available")
    
    app.run(host="0.0.0.0", port=PORT, debug=True)