import argparse
import requests
from colorama import Fore

requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()

group.add_argument('-hs', '--headers', action='store', nargs='+',
                   help="add multiple headers",
                   metavar="headers")

parser.add_argument('-t', '--target',
                    type=str, help='scan for security headers',
                    metavar='domain.com')

args = parser.parse_args()

if args.target:
    if args.headers:
        security_headers = args.headers
        session = requests.Session()
        no_sec = []
        found_hd = []
        no_dup = []
        no_dup_found = []
        lower = [x.lower() for x in security_headers]
        capital = [x.upper() for x in security_headers]
        resp = session.get(f"{args.target}", verify=False)
        for item, key in resp.headers.items():
            for sec_headers in security_headers:
                if sec_headers == item or lower == item or capital == item:
                    found_hd.append(sec_headers)
                    [no_dup_found.append(x) for x in found_hd if x not in no_dup_found]
        no_dup = ", ".join(no_dup)
        no_dup_found = ", ".join(no_dup_found)
        no_headers = [item for item in security_headers if item not in no_dup_found]
        no_headers = ", ".join(no_headers)
        if "X-XSS-Protection" in no_headers:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.WHITE}The {Fore.GREEN}{no_headers} {Fore.WHITE}header is not defined.. This header stops pages from loading when they detect reflected cross-site scripting (XSS) attacks")
        if "Content-Security-Policy" in no_headers:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.WHITE}The {Fore.GREEN}{no_headers} {Fore.WHITE} header is not defined.. CSP helps to protect a website and the site visitors from Cross Site Scripting (XSS) attacks and from data injection attacks")
        if "Strict-Transport-Security" in no_headers:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.WHITE}The {Fore.GREEN}{no_headers} {Fore.WHITE} header is not defined.. HSTS prevents an attacker from downgrading the HTTPS connection to an HTTP connection which then allows the attacker to take advantage of insecure redirects.")
        if "X-Content-Type-Options" in no_headers:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.WHITE}The {Fore.GREEN}{no_headers} {Fore.WHITE} header is not defined.. This security header stops certain kinds of exploits that can happen, for example, through malicious user-generated content.") 
        if "X-Frame-Options" in no_headers:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.WHITE}The {Fore.GREEN}{no_headers} {Fore.WHITE} header is not defined.. The X-Frame-Options security header helps stop click-jacking attacks.")