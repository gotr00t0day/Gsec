from colorama import Fore
from modules import fetch_requests, scan, urltoip, sub_output
from utils import path_traversal, portscanner, loginscanner, techscanner, cmsscanner, passive_recon, crawler, api_scanner, api_fuzzer
from utils import param_finder, javascript_scanner, headers, wafscanner, source
from plugins import phpcheck, optionscheck, shellshock, robots, favicon, auth_tokens, cookies_check, sitemap, securitytxt, geolocation
from exploits import f5bigip_scanner
from vuln_db import hostheader_injection, nuclei_vulns, corsmisconfig, crossdomain, head_vuln, cache_poisoning, webservers_vulns, nmap_vuln, xss, broken_links
from vuln_db import openredirect
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

version = "v2.1"

banner = f"""
    .__________________________.
    | .___________________. |==|            {Fore.YELLOW}Web Security Scanner{Fore.RESET}
    | | ................. | |  |
    | | :::GSec Running!::| |  |            {Fore.YELLOW}Author:     {Fore.MAGENTA}c0d3ninja{Fore.RESET}
    | | ::::::::::::::::: | |  |            {Fore.YELLOW}Version:    {Fore.MAGENTA}{version}{Fore.RESET}
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
                   help="Passive recon on the target")

group.add_argument('-px', '--proxy', action='store_true',
                   help="Proxy support")

parser.add_argument('-t', '--target',
                   help="Target to scan",)

parser.add_argument('-pl', '--pluginlist', action='store_true',
                   help="list of plugins")

parser.add_argument('-u', '--updatetemplates', action='store_true',
                   help="Update nuclei templates")

parser.add_argument('-us', '--ultimatescan', help="Target to scan")

parser.add_argument('-ug', '--updategsec', action='store_true', help="Update GSec")

parser.add_argument('-un', '--updatenuclei', action='store_true', help="Update Nuclei")

parser.add_argument('-v', '--version', action='store_true', help="Gsec version")

args = parser.parse_args()


if args.pluginlist:
    filenames = os.listdir("plugins")
    filenames.remove("__init__.py")
    file_desc = {}
    for filename in filenames:
        if filename.endswith(".py"):
            if "securitytxt.py" in filename:
                file_desc["securitytxt.py"] = " - security.txt is a proposed standard which allows websites to define security policies and contact details.\n"
            if "auth_tokens.py" in filename:
                file_desc["auth_token.py"] = " - Find authentication token leaks\n"
            if "optionscheck.py" in filename:
                file_desc["optionscheck.py"] = " - OPTIONS method determines the communication options available for a specific resource\n"
            if "sitemap.py" in filename:
                file_desc["sitemap.py"] = " - A sitemap is a file where a developer or organization can provide information about the pages, videos, and other files offered by the site or application\n"    
            if "favicon.py" in filename:
                file_desc["favicon.py"] = " - Fetches favicon.ico and calculates its hash value to find assets in shodan.\n"
            if "phpcheck.py" in filename:
                file_desc["phpcheck.py"] = " - Checks a domain for PHP\n"
            if "shellshock.py" in filename:
                file_desc["shellshock.py"] = " - Scan a domain to find the shellshock vulnerability\n"
            if "agent_list.py" in filename:
                file_desc["agent_list.py"] = " - A list of user agents\n" 
            if "robots.py" in filename:
                file_desc["robots.py"] = " - Checks for the robots.txt file\n" 
            if "cookies_check.py" in filename:
                file_desc["cookies_check.py"] = " - Prints the PHP SESSID cookies\n"          
    for k,v in file_desc.items():
        print(f"{k}{v}")

if args.version:
    print(f"{Fore.YELLOW}Gsec {Fore.MAGENTA}{version}")

if args.updategsec:
    scan.commands("git pull")

if args.updatetemplates:
    scan.commands("nuclei -ut")

if args.updatenuclei:
    scan.commands("nuclei -update")

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
            geolocation.scan_ip(args.target)
            optionscheck.Get_Options(args.target)
            portscanner.portscanner(args.target)
            fetch_requests.get_headers(args.target)
            headers.get_headers(args.target)
            scan.commands(f"python3 {os.path.abspath(os.getcwd())}/utils/securityheaders.py --target {args.target} --headers X-XSS-Protection")
            scan.commands(f"python3 {os.path.abspath(os.getcwd())}/utils/securityheaders.py --target {args.target} --headers Content-Security-Policy")
            scan.commands(f"python3 {os.path.abspath(os.getcwd())}/utils/securityheaders.py --target {args.target} --headers Strict-Transport-Security")
            scan.commands(f"python3 {os.path.abspath(os.getcwd())}/utils/securityheaders.py --target {args.target} --headers X-Content-Type-Options")
            scan.commands(f"python3 {os.path.abspath(os.getcwd())}/utils/securityheaders.py --target {args.target} --headers X-Frame-Options")
            source.page_source(args.target)
            crawler.scan(args.target)
            wafscanner.main(args.target)
            cmsscanner.main(args.target)
            phpcheck.php_ident(args.target)
            techscanner.Tech(args.target)
            robots.robots_scan(args.target)
            sitemap.sitemap(args.target)
            cookies_check.phpsessid_session(args.target)
            auth_tokens.auth_tokens(args.target)
            favicon.favicon_hash(args.target)
            nuclei_vulns.nuclei_scan(args.target)
            shellshock.shellshock_scan(args.target)
            corsmisconfig.cors_scan(args.target)
            crossdomain.crossdomain_misconfig(args.target)
            hostheader_injection.host_header_injection(args.target)
            head_vuln.head_auth_bypass(args.target)
            cache_poisoning.cache_dos_scan(args.target)
            webservers_vulns.Servers_scan(args.target)
            openredirect.scan(args.target)
            sub_output.subpro_scan(f"python3 {os.path.abspath(os.getcwd())}/vuln_db/ssrf.py {args.target}")
            sub_output.subpro_scan(f"python3 {os.path.abspath(os.getcwd())}/vuln_db/openredirect.py {args.target}")
            path_traversal.path_traversal_scan(args.target)
            f5bigip_scanner.scan_vuln(args.target)
            crawler.scan(args.target)
            api_scanner.swagger_ui(args.target)
            api_fuzzer.main(args.target)
            param_finder.get_params(args.target)
            javascript_scanner.spider(args.target)
            nmap_vuln.vulners_scan(args.target)
            broken_links.scan(args.target)
            xss.scan(args.target)
            openredirect.scan(args.target)
            #await loginscanner.main(args.target)
            print("\n")
            print(f"\t\t {Fore.MAGENTA} SCAN FINISHED{Fore.LIGHTMAGENTA_EX}!{Fore.MAGENTA}!{Fore.YELLOW}!{Fore.RESET}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except ConnectionError:
        pass
    except TypeError:
        pass
