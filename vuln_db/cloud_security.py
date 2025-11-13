#!/usr/bin/env python3
"""
Cloud Security Scanner
Comprehensive cloud misconfiguration scanner for AWS, Azure, GCP, and containerized environments
"""

from colorama import Fore
import requests
import urllib3
import re
import time
import os
import concurrent.futures
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Tuple, Optional, Any
import logging
import xml.etree.ElementTree as ET

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


class CloudSecurityScanner:
    """Comprehensive Cloud Security and Misconfiguration Scanner"""
    
    def __init__(self, target_url: str):
        self.target = target_url.rstrip('/')
        self.parsed_url = urlparse(self.target)
        self.hostname = self.parsed_url.netloc
        self.base_domain = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        self.findings = []
        self.discovered_buckets = []
        self.exposed_files = []
        
        # Session setup
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Common bucket name patterns
        self.bucket_patterns = []
        self._generate_bucket_patterns()
        
        # Sensitive file patterns
        self.sensitive_files = [
            # Git files
            '.git/HEAD', '.git/config', '.git/index',
            '.git/logs/HEAD', '.gitignore',
            
            # Environment files
            '.env', '.env.local', '.env.production', '.env.development',
            '.env.backup', '.env.old', '.env.save',
            
            # Config files
            'config.json', 'config.yml', 'config.yaml',
            'configuration.json', 'settings.json', 'app.config',
            
            # Backup files
            'backup.zip', 'backup.tar.gz', 'backup.sql',
            'database.sql', 'db.sql', 'dump.sql',
            'backup.tar', 'site.zip', 'www.zip',
            
            # Docker files
            'Dockerfile', 'docker-compose.yml', '.dockerignore',
            
            # Cloud configs
            'terraform.tfstate', 'terraform.tfvars',
            '.aws/credentials', '.aws/config',
            
            # Keys and secrets
            'id_rsa', 'id_rsa.pub', 'authorized_keys',
            'private.key', 'public.key', 'privatekey.pem',
            'server.key', 'certificate.pem',
            
            # Logs
            'error.log', 'access.log', 'debug.log',
            'application.log', 'server.log'
        ]
        
        # Cloud metadata endpoints
        self.metadata_endpoints = {
            'aws': 'http://169.254.169.254/latest/meta-data/',
            'gcp': 'http://metadata.google.internal/computeMetadata/v1/',
            'azure': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'digitalocean': 'http://169.254.169.254/metadata/v1/',
            'alibaba': 'http://100.100.100.200/latest/meta-data/'
        }
        
    def _generate_bucket_patterns(self):
        """Generate potential bucket names based on domain"""
        # Extract domain parts
        domain_parts = self.hostname.replace('www.', '').split('.')
        base_name = domain_parts[0] if domain_parts else 'test'
        
        # Common patterns
        patterns = [
            base_name,
            f"{base_name}-backup",
            f"{base_name}-backups",
            f"{base_name}-prod",
            f"{base_name}-production",
            f"{base_name}-dev",
            f"{base_name}-development",
            f"{base_name}-stage",
            f"{base_name}-staging",
            f"{base_name}-test",
            f"{base_name}-assets",
            f"{base_name}-static",
            f"{base_name}-public",
            f"{base_name}-private",
            f"{base_name}-data",
            f"{base_name}-files",
            f"{base_name}-uploads",
            f"{base_name}-images",
            f"{base_name}-media",
            f"{base_name}-cdn",
            f"{base_name}-logs",
            f"backup-{base_name}",
            f"prod-{base_name}",
            f"dev-{base_name}",
        ]
        
        self.bucket_patterns = patterns
    
    def scan_cloud_security(self):
        """Main cloud security scanning function"""
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}Starting Cloud Security Scan...{Fore.RESET}")
        
        try:
            # Scan for exposed files
            self.scan_exposed_files()
            
            # AWS S3 bucket scanning
            self.scan_aws_s3_buckets()
            
            # Azure blob storage
            self.scan_azure_storage()
            
            # GCP storage buckets
            self.scan_gcp_buckets()
            
            # Cloud metadata endpoints
            self.test_cloud_metadata()
            
            # Docker registry exposure
            self.test_docker_registry()
            
            # Kubernetes exposure
            self.test_kubernetes_exposure()
            
            print(f"{Fore.GREEN}[+] Cloud Security Scan Complete!{Fore.RESET}")
            
        except Exception as e:
            logger.error(f"Error in cloud security scan: {e}")
    
    def scan_exposed_files(self):
        """Scan for exposed sensitive files"""
        print(f"{Fore.CYAN}[*] Scanning for exposed sensitive files...{Fore.RESET}", end='', flush=True)
        
        def check_file(file_path):
            url = f"{self.base_domain}/{file_path}"
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    # Verify it's not a 404 page masquerading as 200
                    if len(response.content) > 0 and '404' not in response.text[:200].lower():
                        return file_path, response
            except:
                pass
            return None
        
        # Use thread pool for faster scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(check_file, self.sensitive_files)
            
            for result in results:
                if result:
                    file_path, response = result
                    self.exposed_files.append(file_path)
                    
                    severity = 'Critical' if any(x in file_path for x in ['.env', 'id_rsa', '.git/', 'terraform.tfstate', '.aws/']) else 'High'
                    
                    self.findings.append({
                        'type': 'Exposed Sensitive File',
                        'severity': severity,
                        'file': file_path,
                        'url': f"{self.base_domain}/{file_path}",
                        'size': len(response.content),
                        'details': f'Sensitive file is publicly accessible'
                    })
        
        if self.exposed_files:
            print(f" {Fore.YELLOW}Found {len(self.exposed_files)} exposed files{Fore.RESET}")
        else:
            print(f" {Fore.GREEN}Done{Fore.RESET}")
    
    def scan_aws_s3_buckets(self):
        """Scan for AWS S3 bucket misconfigurations"""
        print(f"{Fore.CYAN}[*] Scanning AWS S3 buckets...{Fore.RESET}", end='', flush=True)
        
        def check_s3_bucket(bucket_name):
            # Try different S3 endpoint formats
            endpoints = [
                f"https://{bucket_name}.s3.amazonaws.com",
                f"https://s3.amazonaws.com/{bucket_name}",
                f"https://{bucket_name}.s3-us-west-1.amazonaws.com",
                f"https://{bucket_name}.s3-us-east-1.amazonaws.com",
                f"https://{bucket_name}.s3-eu-west-1.amazonaws.com"
            ]
            
            for endpoint in endpoints:
                try:
                    response = self.session.get(endpoint, timeout=5)
                    
                    # Bucket exists
                    if response.status_code == 200:
                        self.discovered_buckets.append(bucket_name)
                        
                        # Check if bucket is listable
                        if '<?xml' in response.text or '<ListBucketResult' in response.text:
                            # Parse bucket contents
                            try:
                                root = ET.fromstring(response.content)
                                files = root.findall('.//{http://s3.amazonaws.com/doc/2006-03-01/}Key')
                                file_count = len(files)
                                
                                self.findings.append({
                                    'type': 'S3 Bucket Misconfiguration',
                                    'severity': 'Critical',
                                    'bucket': bucket_name,
                                    'endpoint': endpoint,
                                    'details': f'S3 bucket is publicly listable with {file_count} files',
                                    'file_count': file_count
                                })
                                return bucket_name, 'listable', file_count
                            except:
                                self.findings.append({
                                    'type': 'S3 Bucket Accessible',
                                    'severity': 'High',
                                    'bucket': bucket_name,
                                    'endpoint': endpoint,
                                    'details': 'S3 bucket is publicly accessible'
                                })
                                return bucket_name, 'accessible', 0
                        else:
                            # Bucket exists but not listable
                            self.findings.append({
                                'type': 'S3 Bucket Found',
                                'severity': 'Medium',
                                'bucket': bucket_name,
                                'endpoint': endpoint,
                                'details': 'S3 bucket exists and is accessible (content not listable)'
                            })
                            return bucket_name, 'exists', 0
                    
                    # Access Denied (bucket exists but not public)
                    elif response.status_code == 403:
                        self.findings.append({
                            'type': 'S3 Bucket Exists (Private)',
                            'severity': 'Info',
                            'bucket': bucket_name,
                            'endpoint': endpoint,
                            'details': 'S3 bucket exists but access is denied (properly configured)'
                        })
                        return bucket_name, 'private', 0
                        
                except Exception as e:
                    pass
            
            return None
        
        # Test bucket patterns
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(check_s3_bucket, self.bucket_patterns[:10]))  # Test first 10
            found_buckets = [r for r in results if r]
        
        if found_buckets:
            print(f" {Fore.YELLOW}Found {len(found_buckets)} S3 buckets{Fore.RESET}")
        else:
            print(f" {Fore.GREEN}Done{Fore.RESET}")
    
    def scan_azure_storage(self):
        """Scan for Azure Blob Storage misconfigurations"""
        print(f"{Fore.CYAN}[*] Scanning Azure blob storage...{Fore.RESET}", end='', flush=True)
        
        def check_azure_storage(storage_name):
            # Azure blob storage endpoints
            endpoints = [
                f"https://{storage_name}.blob.core.windows.net",
                f"https://{storage_name}.blob.core.windows.net/?comp=list"
            ]
            
            for endpoint in endpoints:
                try:
                    response = self.session.get(endpoint, timeout=5)
                    
                    if response.status_code == 200:
                        # Check if container is listable
                        if '<?xml' in response.text or 'EnumerationResults' in response.text:
                            self.findings.append({
                                'type': 'Azure Storage Misconfiguration',
                                'severity': 'Critical',
                                'storage': storage_name,
                                'endpoint': endpoint,
                                'details': 'Azure blob storage is publicly listable'
                            })
                            return storage_name, 'listable'
                        else:
                            self.findings.append({
                                'type': 'Azure Storage Accessible',
                                'severity': 'High',
                                'storage': storage_name,
                                'endpoint': endpoint,
                                'details': 'Azure blob storage is publicly accessible'
                            })
                            return storage_name, 'accessible'
                            
                except:
                    pass
            
            return None
        
        # Test with bucket patterns
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(check_azure_storage, self.bucket_patterns[:10]))
            found_storage = [r for r in results if r]
        
        if found_storage:
            print(f" {Fore.YELLOW}Found {len(found_storage)} Azure storage accounts{Fore.RESET}")
        else:
            print(f" {Fore.GREEN}Done{Fore.RESET}")
    
    def scan_gcp_buckets(self):
        """Scan for GCP Cloud Storage misconfigurations"""
        print(f"{Fore.CYAN}[*] Scanning GCP storage buckets...{Fore.RESET}", end='', flush=True)
        
        def check_gcp_bucket(bucket_name):
            # GCP storage endpoints
            endpoints = [
                f"https://storage.googleapis.com/{bucket_name}",
                f"https://{bucket_name}.storage.googleapis.com"
            ]
            
            for endpoint in endpoints:
                try:
                    response = self.session.get(endpoint, timeout=5)
                    
                    if response.status_code == 200:
                        # Check if bucket is listable
                        if '<?xml' in response.text or '<ListBucketResult' in response.text:
                            self.findings.append({
                                'type': 'GCP Bucket Misconfiguration',
                                'severity': 'Critical',
                                'bucket': bucket_name,
                                'endpoint': endpoint,
                                'details': 'GCP storage bucket is publicly listable'
                            })
                            return bucket_name, 'listable'
                        else:
                            self.findings.append({
                                'type': 'GCP Bucket Accessible',
                                'severity': 'High',
                                'bucket': bucket_name,
                                'endpoint': endpoint,
                                'details': 'GCP storage bucket is publicly accessible'
                            })
                            return bucket_name, 'accessible'
                            
                except:
                    pass
            
            return None
        
        # Test with bucket patterns
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(check_gcp_bucket, self.bucket_patterns[:10]))
            found_buckets = [r for r in results if r]
        
        if found_buckets:
            print(f" {Fore.YELLOW}Found {len(found_buckets)} GCP buckets{Fore.RESET}")
        else:
            print(f" {Fore.GREEN}Done{Fore.RESET}")
    
    def test_cloud_metadata(self):
        """Test for accessible cloud metadata endpoints"""
        print(f"{Fore.CYAN}[*] Testing cloud metadata endpoints...{Fore.RESET}", end='', flush=True)
        
        # Test if we can reach metadata endpoints (SSRF)
        for provider, endpoint in self.metadata_endpoints.items():
            test_url = f"{self.base_domain}/redirect?url={endpoint}"
            
            try:
                # Test common SSRF vectors
                ssrf_params = ['url', 'redirect', 'uri', 'path', 'continue', 'dest', 'destination', 'next']
                
                for param in ssrf_params:
                    test_url = f"{self.base_domain}?{param}={endpoint}"
                    try:
                        response = self.session.get(test_url, timeout=3, allow_redirects=False)
                        
                        # Check if response contains metadata patterns
                        metadata_patterns = ['instance-id', 'ami-id', 'hostname', 'local-ipv4', 'computeMetadata']
                        if any(pattern in response.text for pattern in metadata_patterns):
                            self.findings.append({
                                'type': 'Cloud Metadata Exposure',
                                'severity': 'Critical',
                                'provider': provider,
                                'endpoint': endpoint,
                                'details': f'Cloud metadata endpoint accessible via SSRF parameter: {param}'
                            })
                            break
                    except:
                        pass
            except:
                pass
        
        print(f" {Fore.GREEN}Done{Fore.RESET}")
    
    def test_docker_registry(self):
        """Test for exposed Docker registry"""
        print(f"{Fore.CYAN}[*] Testing Docker registry exposure...{Fore.RESET}", end='', flush=True)
        
        # Common Docker registry endpoints
        registry_paths = [
            '/v2/',
            '/v2/_catalog',
            '/v2/registry/manifests/latest',
            '/_catalog'
        ]
        
        for path in registry_paths:
            url = f"{self.base_domain}{path}"
            try:
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200:
                    # Check for Docker registry indicators
                    if 'repositories' in response.text or 'Docker-Distribution-Api-Version' in response.headers:
                        self.findings.append({
                            'type': 'Exposed Docker Registry',
                            'severity': 'High',
                            'endpoint': url,
                            'details': 'Docker registry is publicly accessible without authentication'
                        })
                        break
            except:
                pass
        
        print(f" {Fore.GREEN}Done{Fore.RESET}")
    
    def test_kubernetes_exposure(self):
        """Test for Kubernetes dashboard and API exposure"""
        print(f"{Fore.CYAN}[*] Testing Kubernetes exposure...{Fore.RESET}", end='', flush=True)
        
        # Kubernetes dashboard and API endpoints
        k8s_endpoints = [
            '/api/v1',
            '/api/v1/namespaces',
            '/api/v1/pods',
            '/apis',
            '/healthz',
            '/metrics'
        ]
        
        # Test on common Kubernetes ports
        k8s_ports = [8001, 8080, 10250, 10251, 10252, 10255, 6443]
        
        # Test current domain first
        for path in k8s_endpoints:
            url = f"{self.base_domain}{path}"
            try:
                response = self.session.get(url, timeout=3)
                
                if response.status_code == 200:
                    # Check for Kubernetes indicators
                    if 'kind' in response.text or 'apiVersion' in response.text or 'kubernetes' in response.text.lower():
                        self.findings.append({
                            'type': 'Exposed Kubernetes API',
                            'severity': 'Critical',
                            'endpoint': url,
                            'details': 'Kubernetes API is publicly accessible without authentication'
                        })
                        break
            except:
                pass
        
        print(f" {Fore.GREEN}Done{Fore.RESET}")
    
    def generate_report(self):
        """Generate comprehensive cloud security report"""
        output_dir = os.path.join(os.path.dirname(__file__), '..', 'output')
        os.makedirs(output_dir, exist_ok=True)
        
        target_name = self.hostname.replace('.', '_')
        report_file = os.path.join(output_dir, f'cloud_security_{target_name}.txt')
        
        with open(report_file, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("CLOUD SECURITY & MISCONFIGURATION SCAN REPORT\n")
            f.write("=" * 70 + "\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Domain: {self.hostname}\n")
            f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 70 + "\n\n")
            
            # Summary section
            f.write("SCAN SUMMARY:\n")
            f.write("-" * 70 + "\n")
            f.write(f"Exposed Sensitive Files: {len(self.exposed_files)}\n")
            f.write(f"Cloud Storage Buckets Found: {len(self.discovered_buckets)}\n")
            f.write(f"Total Findings: {len(self.findings)}\n")
            f.write("\n")
            
            if not self.findings:
                f.write("✅ No critical cloud misconfigurations found!\n\n")
                f.write("BEST PRACTICES:\n")
                f.write("-" * 70 + "\n")
                f.write("✓ Keep cloud storage buckets private by default\n")
                f.write("✓ Enable access logging for all storage buckets\n")
                f.write("✓ Never expose .git directories or .env files\n")
                f.write("✓ Implement proper IAM policies\n")
                f.write("✓ Regular security audits of cloud resources\n")
                f.write("✓ Use cloud-native security tools\n")
                print(f"{Fore.GREEN}[+] Cloud security report saved to: {report_file}{Fore.RESET}")
                return
            
            # Group findings by severity
            severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
            for finding in self.findings:
                severity_count[finding['severity']] += 1
            
            f.write("VULNERABILITIES FOUND:\n")
            f.write("-" * 70 + "\n")
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                count = severity_count[severity]
                if count > 0:
                    f.write(f"{severity}: {count} issue(s)\n")
            f.write("\n")
            
            # Exposed files section
            if self.exposed_files:
                f.write("EXPOSED SENSITIVE FILES:\n")
                f.write("-" * 70 + "\n")
                for file in self.exposed_files[:20]:
                    f.write(f"  • {file}\n")
                if len(self.exposed_files) > 20:
                    f.write(f"  ... and {len(self.exposed_files) - 20} more\n")
                f.write("\n")
            
            # Detailed findings
            f.write("DETAILED FINDINGS:\n")
            f.write("-" * 70 + "\n\n")
            
            for i, finding in enumerate(self.findings, 1):
                f.write(f"{i}. [{finding['severity']}] {finding['type']}\n")
                
                if 'file' in finding:
                    f.write(f"   File: {finding['file']}\n")
                if 'url' in finding:
                    f.write(f"   URL: {finding['url']}\n")
                if 'bucket' in finding:
                    f.write(f"   Bucket: {finding['bucket']}\n")
                if 'storage' in finding:
                    f.write(f"   Storage: {finding['storage']}\n")
                if 'endpoint' in finding:
                    f.write(f"   Endpoint: {finding['endpoint']}\n")
                if 'details' in finding:
                    f.write(f"   Details: {finding['details']}\n")
                if 'file_count' in finding and finding['file_count'] > 0:
                    f.write(f"   Files Exposed: {finding['file_count']}\n")
                f.write("\n")
            
            # Recommendations
            f.write("\nRECOMMENDATIONS:\n")
            f.write("-" * 70 + "\n")
            
            if severity_count['Critical'] > 0:
                f.write("\n🚨 CRITICAL PRIORITY:\n\n")
                
                if any('.env' in str(f.get('file', '')) for f in self.findings):
                    f.write("• Environment Files (.env):\n")
                    f.write("  - Immediately remove .env files from public access\n")
                    f.write("  - Rotate all exposed credentials and API keys\n")
                    f.write("  - Add .env to .gitignore if using version control\n")
                    f.write("  - Use secret management services (AWS Secrets Manager, Azure Key Vault)\n\n")
                
                if any('.git' in str(f.get('file', '')) for f in self.findings):
                    f.write("• Git Repository Exposure:\n")
                    f.write("  - Remove .git directory from production servers immediately\n")
                    f.write("  - This exposes entire source code and commit history\n")
                    f.write("  - Check for exposed credentials in git history\n")
                    f.write("  - Use .gitignore to prevent accidental exposure\n\n")
                
                if any('S3 Bucket' in f['type'] and f['severity'] == 'Critical' for f in self.findings):
                    f.write("• S3 Bucket Misconfigurations:\n")
                    f.write("  - Disable public access on all S3 buckets immediately\n")
                    f.write("  - Enable Block Public Access at account level\n")
                    f.write("  - Review and restrict bucket policies\n")
                    f.write("  - Enable S3 access logging\n")
                    f.write("  - Use IAM roles instead of public access\n\n")
                
                if any('Metadata' in f['type'] for f in self.findings):
                    f.write("• Cloud Metadata Exposure:\n")
                    f.write("  - Fix SSRF vulnerabilities allowing metadata access\n")
                    f.write("  - Implement strict URL validation\n")
                    f.write("  - Use allowlists for external requests\n")
                    f.write("  - Enable IMDSv2 on AWS instances\n\n")
                
                if any('Kubernetes' in f['type'] for f in self.findings):
                    f.write("• Kubernetes Exposure:\n")
                    f.write("  - Secure Kubernetes API with authentication\n")
                    f.write("  - Never expose dashboard publicly\n")
                    f.write("  - Use RBAC (Role-Based Access Control)\n")
                    f.write("  - Implement network policies\n\n")
            
            if severity_count['High'] > 0:
                f.write("\n⚠️  HIGH PRIORITY:\n\n")
                
                if any('terraform' in str(f.get('file', '')).lower() for f in self.findings):
                    f.write("• Terraform State Files:\n")
                    f.write("  - Remove terraform.tfstate from public access\n")
                    f.write("  - Use remote state storage with encryption\n")
                    f.write("  - Never commit state files to version control\n\n")
                
                if any('Docker' in f['type'] for f in self.findings):
                    f.write("• Docker Registry:\n")
                    f.write("  - Implement authentication on Docker registry\n")
                    f.write("  - Use private registries (Docker Hub private, ECR, GCR)\n")
                    f.write("  - Scan images for vulnerabilities\n\n")
                
                if any('backup' in str(f.get('file', '')).lower() for f in self.findings):
                    f.write("• Backup Files:\n")
                    f.write("  - Remove all backup files from web-accessible directories\n")
                    f.write("  - Store backups in secure, private storage\n")
                    f.write("  - Encrypt backup files\n")
                    f.write("  - Implement proper backup rotation\n\n")
            
            if severity_count['Medium'] > 0:
                f.write("\nℹ️  MEDIUM PRIORITY:\n\n")
                f.write("• Implement comprehensive security auditing\n")
                f.write("• Enable CloudTrail/Azure Monitor/GCP Cloud Audit Logs\n")
                f.write("• Regular security assessments of cloud resources\n")
                f.write("• Implement least privilege access policies\n")
                f.write("• Use cloud security posture management tools\n\n")
            
            f.write("\nGENERAL SECURITY BEST PRACTICES:\n")
            f.write("-" * 70 + "\n")
            f.write("1. Never store credentials in code or config files\n")
            f.write("2. Use environment variables or secret management services\n")
            f.write("3. Implement proper access controls on all cloud resources\n")
            f.write("4. Enable encryption at rest and in transit\n")
            f.write("5. Regular security audits and penetration testing\n")
            f.write("6. Monitor for unusual access patterns\n")
            f.write("7. Keep cloud services and dependencies up to date\n")
            f.write("8. Implement multi-factor authentication (MFA)\n")
            f.write("9. Use VPC/VNet for network isolation\n")
            f.write("10. Regular backup and disaster recovery testing\n")
        
        print(f"{Fore.GREEN}[+] Cloud security report saved to: {report_file}{Fore.RESET}")
        
        # Console summary
        if self.findings:
            critical_high = severity_count['Critical'] + severity_count['High']
            if critical_high > 0:
                print(f"{Fore.RED}[!] CRITICAL: Found {critical_high} critical/high severity cloud misconfigurations!{Fore.RESET}")
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}Total findings: {len(self.findings)} ({severity_count['Critical']} Critical, {severity_count['High']} High, {severity_count['Medium']} Medium){Fore.RESET}")
        else:
            print(f"{Fore.GREEN}[+] No critical cloud misconfigurations found!{Fore.RESET}")


def cloud_security_scan(target: str):
    """Main function to run comprehensive cloud security scan"""
    scanner = CloudSecurityScanner(target)
    scanner.scan_cloud_security()
    scanner.generate_report()
    return scanner.findings

