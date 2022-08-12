from colorama import Fore
from modules import fetch_requests, urltoip
from utils import portscanner, loginscanner, techscanner, cmsscanner, passive_recon
from plugins import phpcheck, optionscheck
from vuln_db import hostheader_injection, nginx_vulns
import argparse
import subprocess
import os

##################################################################################
#                          Good Security Scanner
##################################################################################
#
# Gsec Scans a target to look for security issues and misconfigurations
# 
##################################################################################

banner = f"""

{Fore.YELLOW}Web Security Scanner
{Fore.RESET}

              ,~,
             ((()-                   - GSec beta-v0.7
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

group.add_argument('-p', '--passive_recon', action='store_true',
                   help="passive recon on the target")

parser.add_argument('-t', '--target',
                   help="target to scan",
                   metavar="https://www.domain.com")

parser.add_argument('-u', '--updatetemplates', action='store_true',
                   help="update nuclei templates")

args = parser.parse_args()


if args.updatetemplates:
    commands("nuclei -ut")


if args.target:
    if args.passive_recon:
        passive_recon.whois_scan(args.target)
        passive_recon.dns_info(args.target)
        passive_recon.shodan_search(args.target)
    else:
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
        commands(f"python3 {os.path.abspath(os.getcwd())}/utils/subdomainscanner.py {args.target}")
        nginx_vulns.nginx_vulnscan(args.target)
        loginscanner.admin_list(args.target)
        hostheader_injection.host_header_injection(args.target)
        print("\n")
        print(f"\t\t {Fore.MAGENTA} SCAN FINISHED{Fore.LIGHTMAGENTA_EX}!{Fore.MAGENTA}!{Fore.YELLOW}!{Fore.RESET}")
