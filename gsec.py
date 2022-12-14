from colorama import Fore
from modules import fetch_requests, scan, urltoip
from utils import portscanner, loginscanner, techscanner, cmsscanner, passive_recon, path_traversal, crawler, osdetect
from plugins import phpcheck, optionscheck, shellshock, robots, favicon, auth_tokens
from vuln_db import hostheader_injection, nuclei_vulns, corsmisconfig, crossdomain, head_vuln
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


    .__________________________.              
    | .___________________. |==|            {Fore.YELLOW}Web Security Scanner{Fore.RESET}        
    | | ................. | |  |            
    | | :::GSec Running!::| |  |            {Fore.YELLOW}Author:     {Fore.MAGENTA}c0d3ninja{Fore.RESET} 
    | | ::::::::::::::::: | |  |            {Fore.YELLOW}Version:    {Fore.MAGENTA}beta-v0.23{Fore.RESET}
    | | :1337 bugs found!:| |  |            {Fore.YELLOW}Instagram:  {Fore.MAGENTA}gotr00t0day{Fore.RESET}
    | | ::::::::::::::::: | |  |
    | | ::::::::::::::::: | |  |           
    | | ::::::::::::::::: | | ,|            {Fore.CYAN}Happy Hacking{Fore.LIGHTMAGENTA_EX}!{Fore.MAGENTA}!{Fore.YELLOW}!{Fore.RESET}
    | !___________________! |(c|
    !_______________________!__!
   /                            \\
  /  [][][][][][][][][][][][][]  \\
 /  [][][][][][][][][][][][][][]  \\
(  [][][][][____________][][][][]  )
 \ ------------------------------ /
  \______________________________/ 


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

parser.add_argument('-us', '--ultimatescan', help="target to scan")

parser.add_argument('-ug', '--updategsec', action='store_true', help="target to scan")

args = parser.parse_args()

if args.updategsec:
    scan.commands("git pull")

if args.updatetemplates:
    scan.commands("nuclei -ut")

if args.ultimatescan:
    nuclei_vulns.nuclei_ultimate_scan(args.target)


async def main():
    if args.target:
        if args.passive_recon:
            await asyncio.gather(
                passive_recon.whois_scan(args.target),
                passive_recon.dns_info(args.target),
                passive_recon.shodan_search(args.target),
                passive_recon.waybackurls_scan(args.target),
                passive_recon.certsh(args.target),
                passive_recon.domains(args.target)
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
            osdetect.osdetection_scan(args.target)
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
            nuclei_vulns.nuclei_fuzzing_scan(args.target)
            shellshock.shellshock_scan(args.target)
            corsmisconfig.cors_scan(args.target)
            crossdomain.crossdomain_misconfig(args.target)
            hostheader_injection.host_header_injection(args.target)
            head_vuln.head_auth_bypass(args.target)
            path_traversal.path_traversal_scan(args.target)
            crawler.scan(args.target)
            await loginscanner.main(args.target)
            print("\n")
            print(f"\t\t {Fore.MAGENTA} SCAN FINISHED{Fore.LIGHTMAGENTA_EX}!{Fore.MAGENTA}!{Fore.YELLOW}!{Fore.RESET}")

if __name__ == "__main__":
    asyncio.run(main())
