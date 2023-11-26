from modules import sub_output, urltoip
from colorama import Fore
import os

def vulners_scan(domain: str) -> str:
    if "https://" in domain:
        domain = domain.replace("https://", "")
    if "http://" in domain:
        domain = domain.replace("http://", "")
    if "https://www." in domain:
        domain = domain.replace("https://www.", "")
    if "http://www." in domain:
        domain = domain.replace("http://www.", "")
    ip = urltoip.get_ip(domain)
    dir = os.getcwd()
    sub_output.subpro_scan(f"nmap --script vulners, vuln {ip} -v -p80,443 -T4 -Pn > {dir}/output/nmap_results.txt")
    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Nmap Vulnerability Scan: {Fore.MAGENTA}Results saved to /output") 
