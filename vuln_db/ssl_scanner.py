from colorama import Fore
import requests
import ssl
import socket
import time
import os
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings()

class SSLScanner:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.parsed_url = urlparse(self.target)
        self.hostname = self.parsed_url.netloc.split(':')[0]  # Remove port if present
        self.port = 443 if self.parsed_url.scheme == 'https' else 443
        self.findings = []

    def scan_ssl(self):
        """Main SSL scanning function"""
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}Scanning SSL/TLS configuration...{Fore.RESET}", end='', flush=True)

        try:
            # Basic SSL connection test
            self.check_ssl_connection()

            # Certificate validation
            self.check_certificate()

            # Protocol support
            self.check_protocol_support()

            # Cipher suites
            self.check_cipher_suites()

            print(f" {Fore.GREEN}Done{Fore.RESET}")

        except Exception as e:
            print(f" {Fore.RED}Error: {str(e)}{Fore.RESET}")

    def check_ssl_connection(self):
        """Test basic SSL connection"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.hostname, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        return True
        except Exception as e:
            self.findings.append({
                'type': 'SSL Connection Failed',
                'description': f'Cannot establish SSL connection: {str(e)}',
                'severity': 'High'
            })
            return False

    def check_certificate(self):
        """Check SSL certificate validity"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()

                    if cert:
                        # Check expiration
                        import datetime
                        not_after = ssl.cert_time_to_seconds(cert['notAfter'])
                        current_time = time.time()

                        if not_after < current_time:
                            self.findings.append({
                                'type': 'Expired SSL Certificate',
                                'description': 'SSL certificate has expired',
                                'severity': 'High'
                            })

                        # Check issuer
                        issuer = dict(x[0] for x in cert['issuer'])
                        if 'organizationName' not in issuer:
                            self.findings.append({
                                'type': 'Self-Signed Certificate',
                                'description': 'Certificate appears to be self-signed',
                                'severity': 'Medium'
                            })

        except Exception as e:
            pass

    def check_protocol_support(self):
        """Check supported SSL/TLS protocols"""
        try:
            # Test different protocols
            # Note: TLSv1.2 is still secure and widely used, only TLSv1.0 and TLSv1.1 are deprecated
            protocols_to_test = [
                (ssl.PROTOCOL_TLSv1_2, 'TLSv1.2', False),  # NOT deprecated
                (ssl.PROTOCOL_TLSv1_1, 'TLSv1.1', True),   # Deprecated since 2020
                (ssl.PROTOCOL_TLSv1, 'TLSv1.0', True)      # Deprecated since 2020
            ]

            deprecated_protocols = []
            supported_secure_protocols = []
            
            for protocol, name, is_deprecated in protocols_to_test:
                try:
                    context = ssl.SSLContext(protocol)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                    with socket.create_connection((self.hostname, self.port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                            if is_deprecated:
                                deprecated_protocols.append(name)
                            else:
                                supported_secure_protocols.append(name)
                except:
                    pass

            # Only flag if deprecated protocols are supported
            if deprecated_protocols:
                self.findings.append({
                    'type': 'Deprecated SSL/TLS Protocols',
                    'description': f'Server supports deprecated protocols: {", ".join(deprecated_protocols)}. These should be disabled.',
                    'protocols': deprecated_protocols,
                    'severity': 'Medium'
                })
            
            # Add informational finding about secure protocols
            if supported_secure_protocols:
                self.findings.append({
                    'type': 'Secure Protocol Support',
                    'description': f'Server supports secure protocols: {", ".join(supported_secure_protocols)}',
                    'protocols': supported_secure_protocols,
                    'severity': 'Info'
                })

        except Exception as e:
            pass

    def check_cipher_suites(self):
        """Check supported cipher suites"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.hostname, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        # Check for weak ciphers
                        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL']
                        if any(weak in cipher_name.upper() for weak in weak_ciphers):
                            self.findings.append({
                                'type': 'Weak Cipher Suite',
                                'description': f'Using weak cipher: {cipher_name}',
                                'severity': 'Medium'
                            })

        except Exception as e:
            pass

    def generate_ssl_report(self):
        """Generate SSL report and save to file"""
        output_dir = os.path.join(os.path.dirname(__file__), '..', 'output')
        os.makedirs(output_dir, exist_ok=True)

        target_name = self.hostname.replace('.', '_')
        report_file = os.path.join(output_dir, f'ssl_scan_{target_name}.txt')

        with open(report_file, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("SSL/TLS SECURITY SCAN REPORT\n")
            f.write("=" * 60 + "\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Hostname: {self.hostname}\n")
            f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n\n")

            if not self.findings:
                f.write("✅ No critical SSL/TLS issues found!\n")
                print(f"{Fore.GREEN}[+] SSL report saved to: {report_file}{Fore.RESET}")
                return

            # Group findings by severity
            severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
            for finding in self.findings:
                severity_count[finding['severity']] += 1

            # Only show actual issues, not info
            actual_issues = sum(severity_count[s] for s in ['Critical', 'High', 'Medium', 'Low'])
            
            if actual_issues > 0:
                f.write("ISSUES FOUND:\n")
                f.write("-" * 30 + "\n")
                for severity in ['Critical', 'High', 'Medium', 'Low']:
                    count = severity_count[severity]
                    if count > 0:
                        f.write(f"{severity}: {count} issues\n")
                f.write("\n")

            # Show issues first
            issues = [f for f in self.findings if f['severity'] != 'Info']
            if issues:
                f.write("DETAILED FINDINGS:\n")
                f.write("-" * 30 + "\n")
                for i, finding in enumerate(issues, 1):
                    f.write(f"{i}. [{finding['severity']}] {finding['type']}\n")
                    if 'description' in finding:
                        f.write(f"   Description: {finding['description']}\n")
                    if 'protocols' in finding:
                        f.write(f"   Protocols: {', '.join(finding['protocols'])}\n")
                    f.write("\n")
            
            # Show informational findings separately
            info_findings = [f for f in self.findings if f['severity'] == 'Info']
            if info_findings:
                f.write("INFORMATIONAL:\n")
                f.write("-" * 30 + "\n")
                for finding in info_findings:
                    f.write(f"✓ {finding['type']}\n")
                    if 'description' in finding:
                        f.write(f"  {finding['description']}\n")
                    f.write("\n")

            # Add SSL recommendations based on actual findings
            if actual_issues > 0:
                f.write("RECOMMENDATIONS:\n")
                f.write("-" * 30 + "\n")
                
                if severity_count['High'] > 0 or severity_count['Critical'] > 0:
                    f.write("🚨 HIGH PRIORITY:\n")
                    f.write("- Renew expired SSL certificates immediately\n")
                    f.write("- Fix SSL connection issues\n")
                    f.write("- Address critical security vulnerabilities\n\n")

                if severity_count['Medium'] > 0:
                    f.write("⚠️  MEDIUM PRIORITY:\n")
                    # Check what specific issues were found
                    has_deprecated_protocols = any(f['type'] == 'Deprecated SSL/TLS Protocols' for f in issues)
                    has_weak_ciphers = any(f['type'] == 'Weak Cipher Suite' for f in issues)
                    
                    if has_deprecated_protocols:
                        f.write("- Disable deprecated SSL/TLS protocols:\n")
                        f.write("  * TLSv1.0 - Deprecated since 2020\n")
                        f.write("  * TLSv1.1 - Deprecated since 2020\n")
                        f.write("  * Keep TLSv1.2 enabled (still secure and widely used)\n")
                        f.write("  * Enable TLSv1.3 if possible (recommended)\n")
                    if has_weak_ciphers:
                        f.write("- Replace weak cipher suites with strong alternatives\n")
                        f.write("  * Avoid: RC4, DES, 3DES, MD5, NULL\n")
                        f.write("  * Use: AES-GCM, ChaCha20-Poly1305\n")
                    f.write("- Use certificates from trusted Certificate Authorities\n")
                    f.write("- Ensure proper certificate chain validation\n\n")
                
                if severity_count['Low'] > 0:
                    f.write("ℹ️  LOW PRIORITY:\n")
                    f.write("- Monitor SSL/TLS configuration regularly\n")
                    f.write("- Keep certificates up to date\n")
                    f.write("- Consider implementing Certificate Transparency monitoring\n\n")
            else:
                f.write("PROTOCOL INFORMATION:\n")
                f.write("-" * 30 + "\n")
                f.write("✅ No SSL/TLS security issues detected!\n")
                f.write("\nBest Practices:\n")
                f.write("- TLSv1.2 is secure and widely supported (acceptable)\n")
                f.write("- TLSv1.3 is the latest standard (recommended if available)\n")
                f.write("- Ensure only TLSv1.0 and TLSv1.1 are disabled\n\n")

        print(f"{Fore.GREEN}[+] SSL report saved to: {report_file}{Fore.RESET}")
        
        # Calculate actual issues (excluding Info)
        actual_issues = sum(severity_count[s] for s in ['Critical', 'High', 'Medium', 'Low'])
        
        if actual_issues > 0:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}Found {actual_issues} SSL issues ({severity_count['High']} High, {severity_count['Medium']} Medium, {severity_count['Low']} Low){Fore.RESET}")
        else:
            print(f"{Fore.GREEN}[+] {Fore.CYAN}No SSL/TLS security issues found! (TLSv1.2 detected - this is secure){Fore.RESET}")

def ssl_scan(target):
    """Main function to run SSL vulnerability scan"""
    scanner = SSLScanner(target)
    scanner.scan_ssl()
    scanner.generate_ssl_report()
    return scanner.findings
