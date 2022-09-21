from colorama import Fore
from modules import fetch_requests, scan, urltoip
from utils import portscanner, loginscanner, techscanner, cmsscanner, passive_recon
from plugins import phpcheck, optionscheck, shellshock, robots, favicon, auth_tokens
from vuln_db import hostheader_injection, nuclei_vulns, corsmisconfig
import argparse
import os
import asyncio

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
             ((()-                   - GSec beta-v0.15
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
    scan.commands("nuclei -ut")

async def main():
    if args.target:
        if args.passive_recon:
            await asyncio.gather(
                passive_recon.whois_scan(args.target),
                passive_recon.dns_info(args.target),
                passive_recon.shodan_search(args.target),
                passive_recon.waybackurls_scan(args.target),
                passive_recon.certsh(args.target),
            )

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
            scan.commands(f"python3 {os.path.abspath(os.getcwd())}/utils/securityheaders.py --target {args.target} --headers X-XSS-Protection")
            scan.commands(f"python3 {os.path.abspath(os.getcwd())}/utils/securityheaders.py --target {args.target} --headers Content-Security-Policy")
            scan.commands(f"python3 {os.path.abspath(os.getcwd())}/utils/securityheaders.py --target {args.target} --headers Strict-Transport-Security")
            scan.commands(f"python3 {os.path.abspath(os.getcwd())}/utils/securityheaders.py --target {args.target} --headers X-Content-Type-Options")
            scan.commands(f"python3 {os.path.abspath(os.getcwd())}/utils/securityheaders.py --target {args.target} --headers X-Frame-Options")
            cmsscanner.main(args.target)
            phpcheck.php_ident(args.target)
            techscanner.Tech(args.target)
            robots.robots_scan(args.target)
            auth_tokens.auth_tokens(args.target)
            favicon.favicon_hash(args.target)
            nuclei_vulns.nuclei_nginx_scan(args.target)
            nuclei_vulns.nuclei_cve_scan(args.target)
            nuclei_vulns.nuclei_headercommandinjection_scan(args.target)
            shellshock.shellshock_scan(args.target)
            corsmisconfig.cors_scan(args.target)
            loginscanner.admin_list(args.target)
            hostheader_injection.host_header_injection(args.target)
            print("\n")
            print(f"\t\t {Fore.MAGENTA} SCAN FINISHED{Fore.LIGHTMAGENTA_EX}!{Fore.MAGENTA}!{Fore.YELLOW}!{Fore.RESET}")

if __name__ == "__main__":
    asyncio.run(main())
