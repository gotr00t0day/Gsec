from colorama import Fore
from modules import fetch_requests, urltoip
from utils import portscanner, securityheaders, loginscanner, techscanner, cmsscanner
from plugins import phpcheck, optionscheck
from vuln_db import hostheader_injection, nginx_vulns, jaeles_scans
import argparse
import subprocess
import os

##################################################################################
#                          Good Security Scanner v1.0 
##################################################################################
#
# Gsec Scans a target to look for security issues and misconfigurations
# 
##################################################################################

banner = f"""

{Fore.YELLOW}Web Security Scanner
{Fore.RESET}

              ,~,
             ((()-                   - GSec beta-v0.1
             -''-.                   - by c0deninja 
            (\  /\)                  - @gotr00t0day (Instagram)
      ~______\) | `\\
   ~~~(         |  ')                {Fore.CYAN}Happy Hacking{Fore.LIGHTMAGENTA_EX}!{Fore.MAGENTA}!{Fore.YELLOW}!{Fore.RESET}
      | )____(  |                    
     /|/     ` /|
     \ \      / |
     |\|\   /| |\\



"""

print(f"{Fore.WHITE}{banner}")


def commands(cmd):
    try:
        subprocess.check_call(cmd, shell=True)
    except:
        pass

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()

parser.add_argument('-t', '--target',
                   help="target to scan",
                   metavar="https://www.domain.com")


args = parser.parse_args()


if args.target:
    fetch_requests.do_requests(args.target)
    ip = urltoip.get_ip(args.target)
    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} IP: {Fore.GREEN}{ip}")
    if "https://" in args.target:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} PROTOCOL: {Fore.GREEN}https")
    if "http://" in args.target:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} PROTOCOL: {Fore.GREEN}http")
    optionscheck.Get_Options(args.target)
    portscanner.portscanner(args.target)
    fetch_requests.get_headers(args.target)
    commands(f"python3 {os.path.abspath(os.getcwd())}/utils/securityheaders.py --target {args.target} --headers X-XSS-Protection")
    commands(f"python3 {os.path.abspath(os.getcwd())}/utils/securityheaders.py --target {args.target} --headers Content-Security-Policy")
    commands(f"python3 {os.path.abspath(os.getcwd())}/utils/securityheaders.py --target {args.target} --headers Strict-Transport-Security")
    commands(f"python3 {os.path.abspath(os.getcwd())}/utils/securityheaders.py --target {args.target} --headers X-Content-Type-Options")
    commands(f"python3 {os.path.abspath(os.getcwd())}/utils/securityheaders.py --target {args.target} --headers X-Frame-Options")
    cmsscanner.main(args.target)
    phpcheck.php_ident(args.target)
    techscanner.Tech(args.target)
    nginx_vulns.nginx_vulnscan(args.target)
    jaeles_scans.fuzz(args.target)
    loginscanner.admin_list(args.target)
    hostheader_injection.host_header_injection(args.target)
    print("\n")
    print(f"\t\t {Fore.MAGENTA} SCAN FINISHED{Fore.LIGHTMAGENTA_EX}!{Fore.MAGENTA}!{Fore.YELLOW}!{Fore.RESET}")
