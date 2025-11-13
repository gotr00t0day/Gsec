#!/usr/bin/env python3
"""
API Security Testing Suite
Comprehensive API vulnerability scanner for REST APIs, GraphQL, and more
"""

from colorama import Fore
import requests
import urllib3
import json
import re
import time
import os
import concurrent.futures
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from typing import Dict, List, Tuple, Optional, Any
import logging

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


class APISecurityScanner:
    """Comprehensive API Security Scanner"""
    
    def __init__(self, target_url: str):
        self.target = target_url.rstrip('/')
        self.parsed_url = urlparse(self.target)
        self.base_domain = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        self.findings = []
        self.discovered_endpoints = []
        
        # Session setup
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Common API paths
        self.common_api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/v1', '/v2', '/v3',
            '/rest', '/rest/v1', '/rest/v2',
            '/graphql', '/gql',
            '/services', '/service',
            '/json', '/xml'
        ]
        
        # Common API endpoints
        self.common_endpoints = [
            'users', 'user', 'admin', 'admins',
            'account', 'accounts', 'profile', 'profiles',
            'auth', 'login', 'logout', 'register',
            'settings', 'config', 'configuration',
            'data', 'info', 'status', 'health',
            'search', 'query', 'list',
            'products', 'items', 'orders',
            'files', 'upload', 'download',
            'messages', 'notifications'
        ]
        
        # HTTP methods to test
        self.http_methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
        
    def scan_api_security(self):
        """Main API security scanning function"""
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}Starting API Security Scan...{Fore.RESET}")
        
        try:
            # Discover API endpoints
            self.discover_api_endpoints()
            
            if not self.discovered_endpoints:
                print(f"{Fore.YELLOW}[!] No API endpoints discovered{Fore.RESET}")
                return
            
            print(f"{Fore.GREEN}[+] Discovered {len(self.discovered_endpoints)} API endpoints{Fore.RESET}")
            
            # Run security tests
            self.test_authentication_bypass()
            self.test_bola_idor()
            self.test_verb_tampering()
            self.test_mass_assignment()
            self.test_rate_limiting()
            self.test_api_versioning()
            self.test_excessive_data_exposure()
            self.test_security_headers()
            self.test_graphql_security()
            
            print(f"{Fore.GREEN}[+] API Security Scan Complete!{Fore.RESET}")
            
        except Exception as e:
            logger.error(f"Error in API security scan: {e}")
    
    def discover_api_endpoints(self):
        """Discover API endpoints"""
        print(f"{Fore.CYAN}[*] Discovering API endpoints...{Fore.RESET}", end='', flush=True)
        
        endpoints_found = []
        
        # Test common API paths
        for path in self.common_api_paths:
            url = f"{self.base_domain}{path}"
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code in [200, 401, 403]:
                    endpoints_found.append(url)
                    
                    # Try common endpoints under this path
                    for endpoint in self.common_endpoints:
                        test_url = f"{url}/{endpoint}"
                        try:
                            r = self.session.get(test_url, timeout=3)
                            if r.status_code in [200, 201, 401, 403, 405]:
                                endpoints_found.append(test_url)
                        except:
                            pass
            except:
                pass
        
        self.discovered_endpoints = list(set(endpoints_found))
        print(f" {Fore.GREEN}Done{Fore.RESET}")
    
    def test_authentication_bypass(self):
        """Test for authentication bypass vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing authentication bypass...{Fore.RESET}", end='', flush=True)
        
        bypass_headers = [
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-Host': 'localhost'},
            {'X-Remote-Addr': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Host': 'localhost'},
        ]
        
        for endpoint in self.discovered_endpoints[:10]:  # Test first 10 to avoid noise
            # Test without auth
            try:
                baseline = self.session.get(endpoint, timeout=5)
                
                # If already accessible, skip
                if baseline.status_code == 200:
                    continue
                
                # Try bypass techniques
                for headers in bypass_headers:
                    response = self.session.get(endpoint, headers=headers, timeout=5)
                    if response.status_code == 200 and baseline.status_code != 200:
                        self.findings.append({
                            'type': 'Authentication Bypass',
                            'severity': 'High',
                            'endpoint': endpoint,
                            'method': 'Header Manipulation',
                            'details': f"Bypassed using headers: {headers}"
                        })
                        break
            except:
                pass
        
        print(f" {Fore.GREEN}Done{Fore.RESET}")
    
    def test_bola_idor(self):
        """Test for BOLA (Broken Object Level Authorization) / IDOR"""
        print(f"{Fore.CYAN}[*] Testing for BOLA/IDOR...{Fore.RESET}", end='', flush=True)
        
        # Pattern to detect numeric IDs, UUIDs, etc.
        id_patterns = [
            r'/(\d+)(?:/|$)',  # Numeric IDs
            r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)',  # UUIDs
            r'[?&]id=(\d+)',  # Query param IDs
            r'[?&]user_id=(\d+)',
            r'[?&]account_id=(\d+)',
        ]
        
        for endpoint in self.discovered_endpoints:
            for pattern in id_patterns:
                matches = re.findall(pattern, endpoint)
                if matches:
                    original_id = matches[0]
                    
                    # Test with different IDs
                    test_ids = ['1', '2', '999', '1000']
                    if original_id.isdigit():
                        test_ids.append(str(int(original_id) + 1))
                    
                    try:
                        baseline = self.session.get(endpoint, timeout=5)
                        
                        for test_id in test_ids:
                            modified_endpoint = re.sub(pattern, f'/{test_id}', endpoint)
                            if modified_endpoint != endpoint:
                                response = self.session.get(modified_endpoint, timeout=5)
                                
                                # Check if we got data we shouldn't have access to
                                if response.status_code == 200 and len(response.content) > 100:
                                    self.findings.append({
                                        'type': 'BOLA/IDOR Vulnerability',
                                        'severity': 'High',
                                        'endpoint': endpoint,
                                        'details': f"Accessible with ID: {test_id}. Possible unauthorized access to other users' data.",
                                        'original_id': original_id,
                                        'test_id': test_id
                                    })
                                    break
                    except:
                        pass
                    break
        
        print(f" {Fore.GREEN}Done{Fore.RESET}")
    
    def test_verb_tampering(self):
        """Test HTTP verb tampering vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing verb tampering...{Fore.RESET}", end='', flush=True)
        
        for endpoint in self.discovered_endpoints[:15]:  # Test subset
            baseline_results = {}
            
            # Test all HTTP methods
            for method in self.http_methods:
                try:
                    response = self.session.request(method, endpoint, timeout=5)
                    baseline_results[method] = {
                        'status': response.status_code,
                        'length': len(response.content)
                    }
                except:
                    baseline_results[method] = None
            
            # Check for suspicious patterns
            # If GET returns 401/403 but PUT/DELETE/PATCH return 200
            if baseline_results.get('GET', {}).get('status') in [401, 403]:
                for method in ['PUT', 'DELETE', 'PATCH', 'POST']:
                    if baseline_results.get(method, {}).get('status') == 200:
                        self.findings.append({
                            'type': 'HTTP Verb Tampering',
                            'severity': 'Medium',
                            'endpoint': endpoint,
                            'details': f"{method} method bypasses authentication while GET is protected",
                            'allowed_method': method
                        })
        
        print(f" {Fore.GREEN}Done{Fore.RESET}")
    
    def test_mass_assignment(self):
        """Test for mass assignment vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing mass assignment...{Fore.RESET}", end='', flush=True)
        
        # Common privileged fields to test
        privileged_fields = [
            'is_admin', 'isAdmin', 'admin', 'role', 'roles',
            'is_staff', 'isStaff', 'staff',
            'permissions', 'privileges',
            'account_type', 'user_type', 'type',
            'verified', 'is_verified', 'isVerified',
            'active', 'is_active', 'isActive',
            'deleted', 'is_deleted'
        ]
        
        for endpoint in self.discovered_endpoints[:10]:
            # Try POST/PUT with privileged fields
            for method in ['POST', 'PUT', 'PATCH']:
                test_data = {field: True for field in privileged_fields[:5]}
                
                try:
                    response = self.session.request(
                        method, 
                        endpoint, 
                        json=test_data,
                        timeout=5
                    )
                    
                    # If we get a success response, it might be vulnerable
                    if response.status_code in [200, 201]:
                        # Check if any privileged fields are in response
                        if any(field in response.text for field in privileged_fields):
                            self.findings.append({
                                'type': 'Potential Mass Assignment',
                                'severity': 'Medium',
                                'endpoint': endpoint,
                                'method': method,
                                'details': 'Endpoint accepts privileged fields that could lead to privilege escalation'
                            })
                            break
                except:
                    pass
        
        print(f" {Fore.GREEN}Done{Fore.RESET}")
    
    def test_rate_limiting(self):
        """Test for rate limiting implementation"""
        print(f"{Fore.CYAN}[*] Testing rate limiting...{Fore.RESET}", end='', flush=True)
        
        # Test first endpoint only to avoid hammering the server
        if self.discovered_endpoints:
            endpoint = self.discovered_endpoints[0]
            
            # Make rapid requests
            responses = []
            for i in range(20):
                try:
                    r = self.session.get(endpoint, timeout=3)
                    responses.append(r.status_code)
                except:
                    pass
            
            # Check if all succeeded (no rate limiting)
            success_count = sum(1 for status in responses if status == 200)
            if success_count >= 18:  # 90%+ success rate
                self.findings.append({
                    'type': 'No Rate Limiting',
                    'severity': 'Low',
                    'endpoint': endpoint,
                    'details': f'Successfully made {success_count}/20 rapid requests without rate limiting'
                })
        
        print(f" {Fore.GREEN}Done{Fore.RESET}")
    
    def test_api_versioning(self):
        """Test API versioning security"""
        print(f"{Fore.CYAN}[*] Testing API versioning...{Fore.RESET}", end='', flush=True)
        
        version_patterns = [
            (r'/v(\d+)/', r'/v{}/'),
            (r'/api/v(\d+)/', r'/api/v{}/'),
            (r'/rest/v(\d+)/', r'/rest/v{}/')
        ]
        
        for endpoint in self.discovered_endpoints:
            for pattern, replacement in version_patterns:
                match = re.search(pattern, endpoint)
                if match:
                    current_version = int(match.group(1))
                    
                    # Test older versions
                    for old_version in range(1, current_version):
                        old_endpoint = re.sub(pattern, replacement.format(old_version), endpoint)
                        try:
                            response = self.session.get(old_endpoint, timeout=5)
                            if response.status_code == 200:
                                self.findings.append({
                                    'type': 'Deprecated API Version Accessible',
                                    'severity': 'Low',
                                    'endpoint': old_endpoint,
                                    'details': f'Old API version v{old_version} is still accessible (current: v{current_version})'
                                })
                        except:
                            pass
                    break
        
        print(f" {Fore.GREEN}Done{Fore.RESET}")
    
    def test_excessive_data_exposure(self):
        """Test for excessive data exposure in API responses"""
        print(f"{Fore.CYAN}[*] Testing excessive data exposure...{Fore.RESET}", end='', flush=True)
        
        # Sensitive field patterns
        sensitive_patterns = [
            r'"password":\s*"[^"]+',
            r'"secret":\s*"[^"]+',
            r'"api_key":\s*"[^"]+',
            r'"apiKey":\s*"[^"]+',
            r'"token":\s*"[^"]+',
            r'"access_token":\s*"[^"]+',
            r'"private_key":\s*"[^"]+',
            r'"credit_card":\s*"[^"]+',
            r'"ssn":\s*"[^"]+',
            r'"social_security":\s*"[^"]+',
        ]
        
        for endpoint in self.discovered_endpoints[:10]:
            try:
                response = self.session.get(endpoint, timeout=5)
                if response.status_code == 200:
                    # Check for sensitive data in response
                    for pattern in sensitive_patterns:
                        matches = re.findall(pattern, response.text, re.IGNORECASE)
                        if matches:
                            self.findings.append({
                                'type': 'Excessive Data Exposure',
                                'severity': 'High',
                                'endpoint': endpoint,
                                'details': f'API exposes sensitive data in response: {pattern.split(":")[0]}'
                            })
                            break
            except:
                pass
        
        print(f" {Fore.GREEN}Done{Fore.RESET}")
    
    def test_security_headers(self):
        """Test for proper API security headers"""
        print(f"{Fore.CYAN}[*] Testing security headers...{Fore.RESET}", end='', flush=True)
        
        required_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Content-Security-Policy',
            'Strict-Transport-Security'
        ]
        
        if self.discovered_endpoints:
            endpoint = self.discovered_endpoints[0]
            try:
                response = self.session.get(endpoint, timeout=5)
                missing_headers = []
                
                for header in required_headers:
                    if header not in response.headers:
                        missing_headers.append(header)
                
                if missing_headers:
                    self.findings.append({
                        'type': 'Missing Security Headers',
                        'severity': 'Low',
                        'endpoint': endpoint,
                        'details': f'Missing headers: {", ".join(missing_headers)}'
                    })
            except:
                pass
        
        print(f" {Fore.GREEN}Done{Fore.RESET}")
    
    def test_graphql_security(self):
        """Test GraphQL-specific security issues"""
        print(f"{Fore.CYAN}[*] Testing GraphQL security...{Fore.RESET}", end='', flush=True)
        
        graphql_paths = ['/graphql', '/gql', '/api/graphql', '/v1/graphql', '/query']
        
        for path in graphql_paths:
            url = f"{self.base_domain}{path}"
            
            # Test introspection query
            introspection_query = {
                'query': '{ __schema { types { name } } }'
            }
            
            try:
                response = self.session.post(url, json=introspection_query, timeout=5)
                if response.status_code == 200 and '__schema' in response.text:
                    self.findings.append({
                        'type': 'GraphQL Introspection Enabled',
                        'severity': 'Medium',
                        'endpoint': url,
                        'details': 'GraphQL introspection is enabled, exposing schema information'
                    })
                    
                    # Test for depth-based DoS
                    deep_query = {
                        'query': '{ ' + 'user { ' * 20 + 'name ' + '}' * 20 + '}'
                    }
                    
                    try:
                        r = self.session.post(url, json=deep_query, timeout=5)
                        if r.status_code == 200:
                            self.findings.append({
                                'type': 'GraphQL Depth Limit Not Enforced',
                                'severity': 'Medium',
                                'endpoint': url,
                                'details': 'GraphQL accepts deeply nested queries, potential DoS vector'
                            })
                    except:
                        pass
            except:
                pass
        
        print(f" {Fore.GREEN}Done{Fore.RESET}")
    
    def generate_report(self):
        """Generate detailed API security report"""
        output_dir = os.path.join(os.path.dirname(__file__), '..', 'output')
        os.makedirs(output_dir, exist_ok=True)
        
        target_name = self.parsed_url.netloc.replace('.', '_')
        report_file = os.path.join(output_dir, f'api_security_{target_name}.txt')
        
        with open(report_file, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("API SECURITY SCAN REPORT\n")
            f.write("=" * 70 + "\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Base Domain: {self.base_domain}\n")
            f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"ENDPOINTS DISCOVERED: {len(self.discovered_endpoints)}\n")
            f.write("-" * 70 + "\n")
            for endpoint in self.discovered_endpoints[:20]:  # Show first 20
                f.write(f"  • {endpoint}\n")
            if len(self.discovered_endpoints) > 20:
                f.write(f"  ... and {len(self.discovered_endpoints) - 20} more\n")
            f.write("\n")
            
            if not self.findings:
                f.write("✅ No API security issues found!\n\n")
                f.write("BEST PRACTICES:\n")
                f.write("-" * 70 + "\n")
                f.write("✓ Implement proper authentication and authorization\n")
                f.write("✓ Use rate limiting to prevent abuse\n")
                f.write("✓ Validate all input data\n")
                f.write("✓ Implement proper error handling\n")
                f.write("✓ Use HTTPS for all API communication\n")
                f.write("✓ Keep API versions up to date\n")
                print(f"{Fore.GREEN}[+] API security report saved to: {report_file}{Fore.RESET}")
                return
            
            # Group findings by severity
            severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            for finding in self.findings:
                severity_count[finding['severity']] += 1
            
            f.write("VULNERABILITIES FOUND:\n")
            f.write("-" * 70 + "\n")
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                count = severity_count[severity]
                if count > 0:
                    f.write(f"{severity}: {count} issue(s)\n")
            f.write("\n")
            
            # Detailed findings
            f.write("DETAILED FINDINGS:\n")
            f.write("-" * 70 + "\n\n")
            
            for i, finding in enumerate(self.findings, 1):
                f.write(f"{i}. [{finding['severity']}] {finding['type']}\n")
                f.write(f"   Endpoint: {finding['endpoint']}\n")
                if 'details' in finding:
                    f.write(f"   Details: {finding['details']}\n")
                if 'method' in finding:
                    f.write(f"   Method: {finding['method']}\n")
                f.write("\n")
            
            # Recommendations
            f.write("\nRECOMMENDATIONS:\n")
            f.write("-" * 70 + "\n")
            
            if severity_count['High'] > 0 or severity_count['Critical'] > 0:
                f.write("\n🚨 CRITICAL/HIGH PRIORITY:\n\n")
                
                if any(f['type'] == 'BOLA/IDOR Vulnerability' for f in self.findings):
                    f.write("• BOLA/IDOR Issues:\n")
                    f.write("  - Implement proper authorization checks for all resources\n")
                    f.write("  - Validate user ownership before returning data\n")
                    f.write("  - Use unpredictable resource identifiers (UUIDs)\n\n")
                
                if any(f['type'] == 'Authentication Bypass' for f in self.findings):
                    f.write("• Authentication Bypass:\n")
                    f.write("  - Validate authentication on server-side only\n")
                    f.write("  - Don't trust client-provided headers for auth decisions\n")
                    f.write("  - Implement proper session management\n\n")
                
                if any(f['type'] == 'Excessive Data Exposure' for f in self.findings):
                    f.write("• Excessive Data Exposure:\n")
                    f.write("  - Implement proper data filtering\n")
                    f.write("  - Never expose sensitive fields in API responses\n")
                    f.write("  - Use DTOs (Data Transfer Objects) to control response data\n\n")
            
            if severity_count['Medium'] > 0:
                f.write("\n⚠️  MEDIUM PRIORITY:\n\n")
                
                if any(f['type'] == 'HTTP Verb Tampering' for f in self.findings):
                    f.write("• HTTP Verb Tampering:\n")
                    f.write("  - Implement consistent authentication across all HTTP methods\n")
                    f.write("  - Explicitly define allowed methods for each endpoint\n\n")
                
                if any(f['type'] == 'Potential Mass Assignment' for f in self.findings):
                    f.write("• Mass Assignment:\n")
                    f.write("  - Use allowlists for accepted input fields\n")
                    f.write("  - Never bind user input directly to database models\n\n")
                
                if any('GraphQL' in f['type'] for f in self.findings):
                    f.write("• GraphQL Security:\n")
                    f.write("  - Disable introspection in production\n")
                    f.write("  - Implement query depth limiting\n")
                    f.write("  - Add query complexity analysis\n\n")
            
            if severity_count['Low'] > 0:
                f.write("\nℹ️  LOW PRIORITY:\n\n")
                f.write("• Implement rate limiting on all endpoints\n")
                f.write("• Add proper security headers\n")
                f.write("• Deprecate and remove old API versions\n")
                f.write("• Implement comprehensive API logging and monitoring\n")
        
        print(f"{Fore.GREEN}[+] API security report saved to: {report_file}{Fore.RESET}")
        
        # Console summary
        if self.findings:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}Found {len(self.findings)} API security issues:")
            print(f"    {severity_count['High']} High, {severity_count['Medium']} Medium, {severity_count['Low']} Low{Fore.RESET}")
        else:
            print(f"{Fore.GREEN}[+] No API security issues found!{Fore.RESET}")


def api_security_scan(target: str):
    """Main function to run comprehensive API security scan"""
    scanner = APISecurityScanner(target)
    scanner.scan_api_security()
    scanner.generate_report()
    return scanner.findings

