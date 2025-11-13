#!/usr/bin/env python3
"""
GraphQL Security Testing Module
Comprehensive GraphQL vulnerability scanner for introspection, DoS, authorization, and more
"""

from colorama import Fore
import requests
import urllib3
import json
import time
import os
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Tuple, Optional, Any
import logging

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


class GraphQLSecurityScanner:
    """Comprehensive GraphQL Security Scanner"""
    
    def __init__(self, target_url: str):
        self.target = target_url.rstrip('/')
        self.parsed_url = urlparse(self.target)
        self.base_domain = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        self.findings = []
        self.graphql_endpoints = []
        self.schema_types = []
        self.queries = []
        self.mutations = []
        
        # Session setup
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Content-Type': 'application/json'
        })
        
        # Common GraphQL endpoints
        self.common_paths = [
            '/graphql',
            '/graphql/',
            '/gql',
            '/gql/',
            '/api/graphql',
            '/api/graphql/',
            '/v1/graphql',
            '/v1/graphql/',
            '/v2/graphql',
            '/query',
            '/api',
            '/api/v1/graphql',
            '/graphiql',
            '/playground',
            '/console'
        ]
        
    def scan_graphql_security(self):
        """Main GraphQL security scanning function"""
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}Starting GraphQL Security Scan...{Fore.RESET}")
        
        try:
            # Discover GraphQL endpoints
            self.discover_graphql_endpoints()
            
            if not self.graphql_endpoints:
                print(f"{Fore.YELLOW}[!] No GraphQL endpoints discovered{Fore.RESET}")
                return
            
            print(f"{Fore.GREEN}[+] Found {len(self.graphql_endpoints)} GraphQL endpoint(s){Fore.RESET}")
            
            # Run security tests on each endpoint
            for endpoint in self.graphql_endpoints:
                print(f"{Fore.CYAN}[*] Testing endpoint: {endpoint}{Fore.RESET}")
                self.current_endpoint = endpoint
                
                # Core security tests
                self.test_introspection()
                self.test_field_suggestions()
                self.test_depth_limit()
                self.test_batch_queries()
                self.test_circular_queries()
                self.test_alias_abuse()
                self.test_directive_overloading()
                self.test_authorization_bypass()
                self.test_information_disclosure()
                self.test_injection_attacks()
            
            print(f"{Fore.GREEN}[+] GraphQL Security Scan Complete!{Fore.RESET}")
            
        except Exception as e:
            logger.error(f"Error in GraphQL security scan: {e}")
            print(f" {Fore.RED}Error: {str(e)}{Fore.RESET}")
    
    def discover_graphql_endpoints(self):
        """Discover GraphQL endpoints"""
        print(f"{Fore.CYAN}[*] Discovering GraphQL endpoints...{Fore.RESET}", end='', flush=True)
        
        for path in self.common_paths:
            url = f"{self.base_domain}{path}"
            
            try:
                # Try GET request first
                response = self.session.get(url, timeout=5)
                if self._is_graphql_endpoint(response, url):
                    self.graphql_endpoints.append(url)
                    continue
                
                # Try POST with simple query
                test_query = {"query": "{ __typename }"}
                response = self.session.post(url, json=test_query, timeout=5)
                if self._is_graphql_endpoint(response, url):
                    self.graphql_endpoints.append(url)
                    
            except Exception as e:
                pass
        
        self.graphql_endpoints = list(set(self.graphql_endpoints))
        print(f" {Fore.GREEN}Done{Fore.RESET}")
    
    def _is_graphql_endpoint(self, response, url: str) -> bool:
        """Check if response indicates a GraphQL endpoint"""
        if response.status_code not in [200, 400, 405]:
            return False
        
        # Check for GraphQL indicators
        indicators = [
            b'"data"',
            b'"errors"',
            b'__schema',
            b'__type',
            b'graphql',
            b'Query',
            b'Mutation',
            b'Subscription'
        ]
        
        # Check response
        content_lower = response.content.lower()
        if any(indicator.lower() in content_lower for indicator in indicators):
            return True
        
        # Check headers
        if 'graphql' in response.headers.get('Content-Type', '').lower():
            return True
        
        return False
    
    def test_introspection(self):
        """Test if introspection queries are enabled"""
        print(f"  {Fore.CYAN}[*] Testing introspection...{Fore.RESET}", end='', flush=True)
        
        # Full introspection query
        introspection_query = {
            "query": """
            {
                __schema {
                    types {
                        name
                        kind
                        description
                        fields {
                            name
                            description
                            type {
                                name
                                kind
                            }
                        }
                    }
                    queryType { name }
                    mutationType { name }
                    subscriptionType { name }
                }
            }
            """
        }
        
        try:
            response = self.session.post(
                self.current_endpoint,
                json=introspection_query,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if 'data' in data and '__schema' in data['data']:
                    schema = data['data']['__schema']
                    self.schema_types = schema.get('types', [])
                    
                    # Extract queries and mutations
                    for type_info in self.schema_types:
                        if type_info.get('name') == 'Query':
                            self.queries = type_info.get('fields', [])
                        elif type_info.get('name') == 'Mutation':
                            self.mutations = type_info.get('fields', [])
                    
                    self.findings.append({
                        'type': 'GraphQL Introspection Enabled',
                        'severity': 'High',
                        'endpoint': self.current_endpoint,
                        'details': f'Full introspection is enabled. Found {len(self.schema_types)} types, {len(self.queries)} queries, {len(self.mutations)} mutations.',
                        'impact': 'Attackers can enumerate entire API schema, discover hidden queries/mutations, and plan targeted attacks.',
                        'types_count': len(self.schema_types),
                        'queries_count': len(self.queries),
                        'mutations_count': len(self.mutations)
                    })
                    
                    print(f" {Fore.RED}ENABLED (Schema exposed!){Fore.RESET}")
                    return
            
        except Exception as e:
            logger.error(f"Introspection test error: {e}")
        
        print(f" {Fore.GREEN}Disabled{Fore.RESET}")
    
    def test_field_suggestions(self):
        """Test field suggestion feature (can leak field names)"""
        print(f"  {Fore.CYAN}[*] Testing field suggestions...{Fore.RESET}", end='', flush=True)
        
        # Query with intentional typo
        suggestion_query = {
            "query": "{ userz { id name } }"  # Typo: 'userz' instead of 'user'
        }
        
        try:
            response = self.session.post(
                self.current_endpoint,
                json=suggestion_query,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Check if suggestions are provided
                if 'errors' in data:
                    error_msg = str(data['errors']).lower()
                    
                    # Look for field suggestions
                    if 'did you mean' in error_msg or 'suggestion' in error_msg or 'user' in error_msg:
                        self.findings.append({
                            'type': 'GraphQL Field Suggestions Enabled',
                            'severity': 'Medium',
                            'endpoint': self.current_endpoint,
                            'details': 'Field name suggestions are enabled in error messages',
                            'evidence': str(data['errors'])[:200],
                            'impact': 'Attackers can enumerate field names through typos and error messages'
                        })
                        print(f" {Fore.YELLOW}Enabled{Fore.RESET}")
                        return
            
        except Exception as e:
            pass
        
        print(f" {Fore.GREEN}Not enabled{Fore.RESET}")
    
    def test_depth_limit(self):
        """Test if query depth limiting is implemented (DoS prevention)"""
        print(f"  {Fore.CYAN}[*] Testing depth limit DoS...{Fore.RESET}", end='', flush=True)
        
        # Deep nested query (20 levels deep)
        deep_query = {
            "query": "{ " + "user { " * 20 + "id " + "}" * 20 + "}"
        }
        
        try:
            start_time = time.time()
            response = self.session.post(
                self.current_endpoint,
                json=deep_query,
                timeout=15
            )
            elapsed = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                
                # If query succeeded or took too long, depth limit not enforced
                if 'data' in data or elapsed > 5.0:
                    self.findings.append({
                        'type': 'No Query Depth Limit',
                        'severity': 'High',
                        'endpoint': self.current_endpoint,
                        'details': f'Deeply nested query (20 levels) was processed. Response time: {elapsed:.2f}s',
                        'impact': 'Vulnerable to depth-based DoS attacks. Attackers can exhaust server resources with deeply nested queries.',
                        'response_time': f'{elapsed:.2f}s'
                    })
                    print(f" {Fore.RED}VULNERABLE (time: {elapsed:.2f}s){Fore.RESET}")
                    return
            
        except requests.exceptions.Timeout:
            self.findings.append({
                'type': 'Query Depth DoS',
                'severity': 'Critical',
                'endpoint': self.current_endpoint,
                'details': 'Deep nested query caused timeout',
                'impact': 'Server is vulnerable to depth-based DoS attacks'
            })
            print(f" {Fore.RED}CRITICAL (Timeout){Fore.RESET}")
            return
        except Exception as e:
            pass
        
        print(f" {Fore.GREEN}Protected{Fore.RESET}")
    
    def test_batch_queries(self):
        """Test batch query attacks (amplification DoS)"""
        print(f"  {Fore.CYAN}[*] Testing batch query attacks...{Fore.RESET}", end='', flush=True)
        
        # Array of same query repeated 50 times
        batch_queries = [
            {"query": "{ __typename }"}
        ] * 50
        
        try:
            start_time = time.time()
            response = self.session.post(
                self.current_endpoint,
                json=batch_queries,
                timeout=15
            )
            elapsed = time.time() - start_time
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    
                    # If array of results returned, batching is allowed
                    if isinstance(data, list) and len(data) > 10:
                        self.findings.append({
                            'type': 'GraphQL Batch Query Allowed',
                            'severity': 'High',
                            'endpoint': self.current_endpoint,
                            'details': f'Batch queries are allowed. Processed {len(data)} queries in {elapsed:.2f}s',
                            'impact': 'Vulnerable to query batching amplification attacks. Can be used for DoS or credential stuffing.',
                            'batch_size': len(data),
                            'response_time': f'{elapsed:.2f}s'
                        })
                        print(f" {Fore.RED}ALLOWED ({len(data)} queries){Fore.RESET}")
                        return
                except:
                    pass
            
        except requests.exceptions.Timeout:
            self.findings.append({
                'type': 'Batch Query DoS',
                'severity': 'Critical',
                'endpoint': self.current_endpoint,
                'details': 'Batch query caused timeout',
                'impact': 'Vulnerable to batch query DoS attacks'
            })
            print(f" {Fore.RED}CRITICAL (Timeout){Fore.RESET}")
            return
        except Exception as e:
            pass
        
        print(f" {Fore.GREEN}Blocked{Fore.RESET}")
    
    def test_circular_queries(self):
        """Test circular/recursive query handling"""
        print(f"  {Fore.CYAN}[*] Testing circular queries...{Fore.RESET}", end='', flush=True)
        
        # Circular query structure
        circular_query = {
            "query": """
            {
                user {
                    friends {
                        friends {
                            friends {
                                friends {
                                    friends {
                                        id
                                    }
                                }
                            }
                        }
                    }
                }
            }
            """
        }
        
        try:
            start_time = time.time()
            response = self.session.post(
                self.current_endpoint,
                json=circular_query,
                timeout=10
            )
            elapsed = time.time() - start_time
            
            if response.status_code == 200 and elapsed > 3.0:
                self.findings.append({
                    'type': 'Circular Query Processing',
                    'severity': 'Medium',
                    'endpoint': self.current_endpoint,
                    'details': f'Circular/recursive queries processed slowly ({elapsed:.2f}s)',
                    'impact': 'May be vulnerable to resource exhaustion via circular queries'
                })
                print(f" {Fore.YELLOW}Slow processing ({elapsed:.2f}s){Fore.RESET}")
                return
                
        except requests.exceptions.Timeout:
            print(f" {Fore.RED}Timeout{Fore.RESET}")
            return
        except Exception as e:
            pass
        
        print(f" {Fore.GREEN}Protected{Fore.RESET}")
    
    def test_alias_abuse(self):
        """Test query alias abuse for amplification"""
        print(f"  {Fore.CYAN}[*] Testing alias abuse...{Fore.RESET}", end='', flush=True)
        
        # Query with many aliases requesting same field
        aliases = '\n'.join([f"alias{i}: __typename" for i in range(100)])
        alias_query = {
            "query": f"{{ {aliases} }}"
        }
        
        try:
            start_time = time.time()
            response = self.session.post(
                self.current_endpoint,
                json=alias_query,
                timeout=10
            )
            elapsed = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                
                if 'data' in data and len(str(data)) > 1000:
                    self.findings.append({
                        'type': 'GraphQL Alias Abuse',
                        'severity': 'Medium',
                        'endpoint': self.current_endpoint,
                        'details': f'Query with 100 aliases processed successfully in {elapsed:.2f}s',
                        'impact': 'Can be used for amplification attacks and resource exhaustion',
                        'response_size': len(str(data))
                    })
                    print(f" {Fore.YELLOW}VULNERABLE{Fore.RESET}")
                    return
            
        except requests.exceptions.Timeout:
            print(f" {Fore.RED}Timeout{Fore.RESET}")
            return
        except Exception as e:
            pass
        
        print(f" {Fore.GREEN}Protected{Fore.RESET}")
    
    def test_directive_overloading(self):
        """Test directive overloading attacks"""
        print(f"  {Fore.CYAN}[*] Testing directive overloading...{Fore.RESET}", end='', flush=True)
        
        # Query with excessive directives
        directive_query = {
            "query": """
            {
                __typename 
                @skip(if: false) 
                @include(if: true) 
                @skip(if: false) 
                @include(if: true)
                @skip(if: false) 
                @include(if: true)
            }
            """
        }
        
        try:
            response = self.session.post(
                self.current_endpoint,
                json=directive_query,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data:
                    self.findings.append({
                        'type': 'Directive Overloading Allowed',
                        'severity': 'Low',
                        'endpoint': self.current_endpoint,
                        'details': 'Multiple directives on same field are processed',
                        'impact': 'Potential for directive-based complexity attacks'
                    })
                    print(f" {Fore.YELLOW}Allowed{Fore.RESET}")
                    return
            
        except Exception as e:
            pass
        
        print(f" {Fore.GREEN}Protected{Fore.RESET}")
    
    def test_authorization_bypass(self):
        """Test for authorization bypass via field access"""
        print(f"  {Fore.CYAN}[*] Testing authorization bypass...{Fore.RESET}", end='', flush=True)
        
        # Try accessing admin/sensitive fields without auth
        sensitive_queries = [
            {"query": "{ admin { users { email password } } }"},
            {"query": "{ users { email password token } }"},
            {"query": "{ me { isAdmin role permissions } }"},
            {"query": "{ allUsers { id email } }"},
        ]
        
        for query in sensitive_queries:
            try:
                response = self.session.post(
                    self.current_endpoint,
                    json=query,
                    timeout=5
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Check if data was returned (not just errors)
                    if 'data' in data and data['data']:
                        # Check if actual data is present
                        data_str = str(data['data']).lower()
                        if any(field in data_str for field in ['email', 'password', 'admin', 'token', 'user']):
                            self.findings.append({
                                'type': 'GraphQL Authorization Bypass',
                                'severity': 'Critical',
                                'endpoint': self.current_endpoint,
                                'details': 'Sensitive fields accessible without authentication',
                                'query': query['query'],
                                'impact': 'Unauthorized access to sensitive user data'
                            })
                            print(f" {Fore.RED}BYPASS FOUND!{Fore.RESET}")
                            return
                
            except Exception as e:
                pass
        
        print(f" {Fore.GREEN}Protected{Fore.RESET}")
    
    def test_information_disclosure(self):
        """Test for information disclosure in errors"""
        print(f"  {Fore.CYAN}[*] Testing information disclosure...{Fore.RESET}", end='', flush=True)
        
        # Invalid query to trigger errors
        error_query = {
            "query": "{ invalid_field_12345 }"
        }
        
        try:
            response = self.session.post(
                self.current_endpoint,
                json=error_query,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if 'errors' in data:
                    errors_str = str(data['errors'])
                    
                    # Check for sensitive information in errors
                    sensitive_patterns = [
                        'path', 'file', 'line', 'stack', 'trace',
                        'exception', 'database', 'sql', 'internal',
                        'server', 'version', 'directory'
                    ]
                    
                    disclosed_info = [p for p in sensitive_patterns if p in errors_str.lower()]
                    
                    if disclosed_info:
                        self.findings.append({
                            'type': 'GraphQL Information Disclosure',
                            'severity': 'Medium',
                            'endpoint': self.current_endpoint,
                            'details': f'Error messages disclose sensitive information: {", ".join(disclosed_info)}',
                            'evidence': errors_str[:300],
                            'impact': 'Internal system details exposed in error messages'
                        })
                        print(f" {Fore.YELLOW}Info leaked{Fore.RESET}")
                        return
            
        except Exception as e:
            pass
        
        print(f" {Fore.GREEN}No leaks{Fore.RESET}")
    
    def test_injection_attacks(self):
        """Test for injection vulnerabilities in GraphQL"""
        print(f"  {Fore.CYAN}[*] Testing injection attacks...{Fore.RESET}", end='', flush=True)
        
        # SQL injection payloads
        injection_payloads = [
            {"query": "{ user(id: \"1' OR '1'='1\") { id } }"},
            {"query": "{ user(id: \"1; DROP TABLE users--\") { id } }"},
            {"query": "{ user(email: \"test@test.com' OR '1'='1\") { id } }"},
        ]
        
        for payload in injection_payloads:
            try:
                response = self.session.post(
                    self.current_endpoint,
                    json=payload,
                    timeout=5
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Check for SQL errors or unexpected data
                    response_str = str(data).lower()
                    if any(err in response_str for err in ['sql', 'syntax error', 'mysql', 'postgres', 'database']):
                        self.findings.append({
                            'type': 'Potential GraphQL Injection',
                            'severity': 'High',
                            'endpoint': self.current_endpoint,
                            'details': 'Injection payload triggered SQL-related error',
                            'payload': payload['query'],
                            'impact': 'May be vulnerable to SQL injection through GraphQL arguments'
                        })
                        print(f" {Fore.RED}VULNERABLE{Fore.RESET}")
                        return
                
            except Exception as e:
                pass
        
        print(f" {Fore.GREEN}Not vulnerable{Fore.RESET}")
    
    def generate_report(self):
        """Generate comprehensive GraphQL security report"""
        output_dir = os.path.join(os.path.dirname(__file__), '..', 'output')
        os.makedirs(output_dir, exist_ok=True)
        
        target_name = self.parsed_url.netloc.replace('.', '_')
        report_file = os.path.join(output_dir, f'graphql_security_{target_name}.txt')
        
        with open(report_file, 'w') as f:
            f.write("=" * 75 + "\n")
            f.write("GRAPHQL SECURITY SCAN REPORT\n")
            f.write("=" * 75 + "\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 75 + "\n\n")
            
            # Endpoints found
            f.write(f"GRAPHQL ENDPOINTS DISCOVERED: {len(self.graphql_endpoints)}\n")
            f.write("-" * 75 + "\n")
            for endpoint in self.graphql_endpoints:
                f.write(f"  • {endpoint}\n")
            f.write("\n")
            
            # Schema information
            if self.schema_types:
                f.write(f"SCHEMA INFORMATION:\n")
                f.write("-" * 75 + "\n")
                f.write(f"Total Types: {len(self.schema_types)}\n")
                f.write(f"Queries: {len(self.queries)}\n")
                f.write(f"Mutations: {len(self.mutations)}\n")
                f.write("\n")
            
            if not self.findings:
                f.write("✅ No critical GraphQL security issues found!\n\n")
                f.write("GRAPHQL SECURITY BEST PRACTICES:\n")
                f.write("-" * 75 + "\n")
                f.write("✓ Disable introspection in production\n")
                f.write("✓ Implement query depth limiting\n")
                f.write("✓ Implement query complexity analysis\n")
                f.write("✓ Rate limit GraphQL endpoints\n")
                f.write("✓ Implement proper field-level authorization\n")
                f.write("✓ Disable batch queries or limit batch size\n")
                f.write("✓ Sanitize error messages\n")
                print(f"{Fore.GREEN}[+] GraphQL security report saved to: {report_file}{Fore.RESET}")
                print(f"{Fore.GREEN}[+] No GraphQL vulnerabilities found!{Fore.RESET}")
                return
            
            # Group findings by severity
            severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            for finding in self.findings:
                severity_count[finding['severity']] += 1
            
            f.write("VULNERABILITIES FOUND:\n")
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
                f.write(f"   Endpoint: {finding['endpoint']}\n")
                if 'details' in finding:
                    f.write(f"   Details: {finding['details']}\n")
                if 'impact' in finding:
                    f.write(f"   Impact: {finding['impact']}\n")
                if 'evidence' in finding:
                    f.write(f"   Evidence: {finding['evidence'][:200]}\n")
                if 'query' in finding:
                    f.write(f"   Query: {finding['query']}\n")
                f.write("\n")
            
            # Recommendations
            f.write("\nRECOMMENDATIONS:\n")
            f.write("-" * 75 + "\n")
            
            if severity_count['Critical'] > 0:
                f.write("\n🚨 CRITICAL PRIORITY:\n\n")
                
                if any('Authorization Bypass' in f['type'] for f in self.findings):
                    f.write("• Authorization Bypass:\n")
                    f.write("  - Implement field-level authorization checks\n")
                    f.write("  - Never rely on client-side field selection for security\n")
                    f.write("  - Use resolver-level authentication\n\n")
                
                if any('DoS' in f['type'] for f in self.findings):
                    f.write("• DoS Vulnerabilities:\n")
                    f.write("  - Implement query depth limiting (max 5-10 levels)\n")
                    f.write("  - Implement query complexity analysis\n")
                    f.write("  - Set maximum query execution time\n\n")
            
            if severity_count['High'] > 0:
                f.write("\n⚠️  HIGH PRIORITY:\n\n")
                
                if any('Introspection' in f['type'] for f in self.findings):
                    f.write("• Introspection:\n")
                    f.write("  - Disable introspection in production environments\n")
                    f.write("  - Use schema documentation instead\n")
                    f.write("  - Implement IP whitelisting for introspection if needed\n\n")
                
                if any('Batch' in f['type'] for f in self.findings):
                    f.write("• Batch Queries:\n")
                    f.write("  - Disable batch queries or limit to 5-10 queries\n")
                    f.write("  - Implement rate limiting per batch\n\n")
                
                if any('Depth' in f['type'] for f in self.findings):
                    f.write("• Query Depth:\n")
                    f.write("  - Set maximum query depth (e.g., 7-10 levels)\n")
                    f.write("  - Use libraries like graphql-depth-limit\n\n")
            
            if severity_count['Medium'] > 0:
                f.write("\nℹ️  MEDIUM PRIORITY:\n\n")
                f.write("• Sanitize error messages in production\n")
                f.write("• Implement query complexity scoring\n")
                f.write("• Add query timeout limits\n")
                f.write("• Monitor for suspicious query patterns\n\n")
            
            f.write("\nGENERAL GRAPHQL SECURITY:\n")
            f.write("-" * 75 + "\n")
            f.write("1. Implement comprehensive authentication and authorization\n")
            f.write("2. Use persisted queries in production\n")
            f.write("3. Implement rate limiting on GraphQL endpoints\n")
            f.write("4. Set query complexity limits and timeouts\n")
            f.write("5. Disable introspection in production\n")
            f.write("6. Use field-level authorization\n")
            f.write("7. Sanitize and validate all inputs\n")
            f.write("8. Monitor GraphQL query patterns\n")
            f.write("9. Use GraphQL-specific security tools\n")
            f.write("10. Regular security audits\n")
        
        print(f"{Fore.GREEN}[+] GraphQL security report saved to: {report_file}{Fore.RESET}")
        
        # Console summary
        if self.findings:
            critical_high = severity_count['Critical'] + severity_count['High']
            if critical_high > 0:
                print(f"{Fore.RED}[!] CRITICAL: Found {critical_high} critical/high severity GraphQL vulnerabilities!{Fore.RESET}")
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}Total findings: {len(self.findings)} ({severity_count['Critical']} Critical, {severity_count['High']} High, {severity_count['Medium']} Medium){Fore.RESET}")
        else:
            print(f"{Fore.GREEN}[+] No GraphQL vulnerabilities found!{Fore.RESET}")


def graphql_security_scan(target: str):
    """Main function to run comprehensive GraphQL security scan"""
    scanner = GraphQLSecurityScanner(target)
    scanner.scan_graphql_security()
    scanner.generate_report()
    return scanner.findings

