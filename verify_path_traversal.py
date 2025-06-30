#!/usr/bin/env python3
"""
Path Traversal Vulnerability Verifier
Checks if path traversal findings are legitimate by analyzing response content
"""

import requests
import re
import os
import sys
import time


class PathTraversalVerifier:
    def __init__(self, output_file="output/path_traversal.txt"):
        self.output_file = output_file
        self.verified_vulns = []
        self.false_positives = []
        
        # Common indicators of successful path traversal
        self.passwd_indicators = [
            r'root:.*?:0:0:',
            r'daemon:.*?:1:1:',
            r'bin:.*?:2:2:',
            r'sys:.*?:3:3:',
            r'nobody:.*?:65534:',
            r'[a-zA-Z0-9_-]+:[x*]?:\d+:\d+:'
        ]
        
        self.windows_indicators = [
            r'\[boot loader\]',
            r'\[operating systems\]',
            r'multi\(0\)disk\(0\)',
            r'default=multi\(',
            r'timeout=\d+'
        ]
        
        self.config_indicators = [
            r'<\?xml.*encoding=',
            r'<configuration>',
            r'connectionStrings',
            r'appSettings',
            r'database.*password',
            r'DB_PASSWORD',
            r'SECRET_KEY'
        ]

    def parse_findings(self):
        """Parse the path_traversal.txt file to extract findings."""
        if not os.path.exists(self.output_file):
            print(f"❌ File not found: {self.output_file}")
            return []
        
        findings = []
        
        with open(self.output_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Split by vulnerability sections
        vuln_sections = re.split(r'--- Vulnerability #\d+ ---', content)
        
        for section in vuln_sections[1:]:  # Skip first empty section
            lines = section.strip().split('\n')
            vuln = {}
            
            for line in lines:
                if line.startswith('URL: '):
                    vuln['url'] = line.replace('URL: ', '').strip()
                elif line.startswith('Parameter: '):
                    vuln['parameter'] = line.replace('Parameter: ', '').strip()
                elif line.startswith('Payload: '):
                    vuln['payload'] = line.replace('Payload: ', '').strip()
                elif line.startswith('Response Info: '):
                    response_info = line.replace('Response Info: ', '').strip()
                    # Parse status and length
                    status_match = re.search(r'Status: (\d+)', response_info)
                    length_match = re.search(r'Length: (\d+)', response_info)
                    if status_match:
                        vuln['status'] = int(status_match.group(1))
                    if length_match:
                        vuln['length'] = int(length_match.group(1))
            
            if 'url' in vuln and 'payload' in vuln:
                findings.append(vuln)
        
        return findings

    def verify_vulnerability(self, vuln):
        """Verify if a path traversal vulnerability is legitimate."""
        try:
            url = vuln['url']
            payload = vuln['payload']
            
            print(f"🔍 Verifying: {url}")
            print(f"   Payload: {payload}")
            
            # Make request with timeout and SSL verification
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=True)
            content = response.text.lower()
            
            # Check for Unix/Linux indicators
            unix_match = any(re.search(pattern, content, re.IGNORECASE) 
                           for pattern in self.passwd_indicators)
            
            # Check for Windows indicators
            windows_match = any(re.search(pattern, content, re.IGNORECASE) 
                              for pattern in self.windows_indicators)
            
            # Check for config file indicators
            config_match = any(re.search(pattern, content, re.IGNORECASE) 
                             for pattern in self.config_indicators)
            
            # Additional checks
            sensitive_content = self.check_sensitive_content(content)
            
            is_vulnerable = unix_match or windows_match or config_match or sensitive_content
            
            result = {
                'url': url,
                'payload': payload,
                'status': response.status_code,
                'length': len(response.text),
                'is_vulnerable': is_vulnerable,
                'indicators': {
                    'unix_passwd': unix_match,
                    'windows_boot': windows_match,
                    'config_files': config_match,
                    'sensitive_content': sensitive_content
                },
                'content_preview': content[:200] if is_vulnerable else None
            }
            
            if is_vulnerable:
                print("   ✅ CONFIRMED VULNERABILITY")
                self.verified_vulns.append(result)
            else:
                print(f"   ❌ False positive (Status: {response.status_code})")
                self.false_positives.append(result)
            
            return result
            
        except requests.exceptions.RequestException as e:
            print(f"   ⚠️  Request failed: {str(e)}")
            return None
        except Exception as e:
            print(f"   ⚠️  Error: {str(e)}")
            return None

    def check_sensitive_content(self, content):
        """Check for other sensitive content indicators."""
        sensitive_patterns = [
            r'password\s*[:=]\s*[\'"][^\'"]+[\'"]',
            r'api[_-]?key\s*[:=]\s*[\'"][^\'"]+[\'"]',
            r'secret\s*[:=]\s*[\'"][^\'"]+[\'"]',
            r'token\s*[:=]\s*[\'"][^\'"]+[\'"]',
            r'mysql.*password',
            r'postgresql.*password',
            r'mongodb.*password'
        ]
        
        return any(re.search(pattern, content, re.IGNORECASE) 
                  for pattern in sensitive_patterns)

    def generate_report(self):
        """Generate a verification report."""
        report_file = "output/path_traversal_verification.txt"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("PATH TRAVERSAL VULNERABILITY VERIFICATION REPORT\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Total findings checked: {len(self.verified_vulns) + len(self.false_positives)}\n")
            f.write(f"Confirmed vulnerabilities: {len(self.verified_vulns)}\n")
            f.write(f"False positives: {len(self.false_positives)}\n\n")
            
            if self.verified_vulns:
                f.write("CONFIRMED VULNERABILITIES:\n")
                f.write("-" * 40 + "\n")
                for i, vuln in enumerate(self.verified_vulns, 1):
                    f.write(f"\n{i}. URL: {vuln['url']}\n")
                    f.write(f"   Payload: {vuln['payload']}\n")
                    f.write(f"   Status: {vuln['status']}\n")
                    f.write(f"   Response Length: {vuln['length']}\n")
                    f.write(f"   Indicators Found: {list(k for k, v in vuln['indicators'].items() if v)}\n")
                    if vuln['content_preview']:
                        f.write(f"   Content Preview: {vuln['content_preview'][:100]}...\n")
            
            if self.false_positives:
                f.write("\n\nFALSE POSITIVES:\n")
                f.write("-" * 40 + "\n")
                for i, fp in enumerate(self.false_positives, 1):
                    f.write(f"\n{i}. URL: {fp['url']}\n")
                    f.write(f"   Payload: {fp['payload']}\n")
                    f.write(f"   Status: {fp['status']} (No sensitive content found)\n")
        
        print(f"\n📋 Verification report saved to: {report_file}")

    def run_verification(self):
        """Main verification process."""
        print("🚀 Starting Path Traversal Verification...")
        
        findings = self.parse_findings()
        if not findings:
            print("❌ No path traversal findings to verify")
            return
        
        print(f"📊 Found {len(findings)} potential vulnerabilities to verify\n")
        
        for i, vuln in enumerate(findings, 1):
            print(f"[{i}/{len(findings)}]", end=" ")
            self.verify_vulnerability(vuln)
            time.sleep(1)  # Be respectful to target server
        
        # Generate report
        self.generate_report()
        
        # Summary
        print("\n🎯 VERIFICATION COMPLETE")
        print(f"   ✅ Confirmed vulnerabilities: {len(self.verified_vulns)}")
        print(f"   ❌ False positives: {len(self.false_positives)}")
        
        if self.verified_vulns:
            print(f"\n⚠️  ATTENTION: {len(self.verified_vulns)} confirmed path traversal vulnerabilities found!")
            print("   Review the verification report for details.")


def main():
    """Main function."""
    if len(sys.argv) > 1:
        output_file = sys.argv[1]
    else:
        output_file = "output/path_traversal.txt"
    
    verifier = PathTraversalVerifier(output_file)
    verifier.run_verification()


if __name__ == "__main__":
    main()