from colorama import Fore
import whois
import dns.resolver
import shodan
import socket
import subprocess
import os


async def whois_scan(domain: str) -> str:
    w = whois.whois(domain)
    name_servers = w.name_servers
    registrar = w.registrar
    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Name Servers: {Fore.GREEN}{', '.join(map(str,name_servers))}")
    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Registrar: {Fore.GREEN}{registrar}")

async def dns_info(domain: str) -> str:
    mx = []
    if "https://" in domain:
        domain = domain.replace("https://", "")
        if "www." in domain:
            domain = domain.replace("www.", "")
    if "http://" in domain:
        domain = domain.replace("http://", "")
        if "www." in domain:
            domain = domain.replace("www.", "")
    try:
        mail_exchange = dns.resolver.resolve(domain, "MX")
        soa = dns.resolver.resolve(domain, "SOA")
        for mail_info in mail_exchange:
            mx.append(mail_info.to_text())
        for state_of_authority in soa:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} SOA: {Fore.GREEN}{state_of_authority.to_text()}")
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} MX: {Fore.GREEN}{', '.join(map(str,mx))}")
    except dns.resolver.NoAnswer:
        pass

async def shodan_search(domain: str) -> str:
    with open(f"core/.shodan", "r") as f:
        key = [x.strip() for x in f.readlines()]
        api = shodan.Shodan(key)
        try:
            results = api.search(domain)
            results_ = []
            results_5 = []
            for result in results['matches']:
                results_.append(result['ip_str'])
            results_5.append(results_[0:9])
            if results_5:
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Shodan IPs: {Fore.GREEN}{', '.join(map(str,results_5))}")
            if not results_5:
                pass
        except shodan.APIError:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.YELLOW} Shodan Key: {Fore.GREEN} Invalid Key")
        except socket.herror:
            pass

async def waybackurls_scan(domain: str) -> str:
    cmd = f"waybackpy --url {domain} --user_agent 'my-user-agent' --known_urls | head -10000"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    check, err = p.communicate()
    check = check.decode()
    with open("output/waybackurls.txt", "w") as f:
        f.writelines(check)
    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Waybackurls: {Fore.GREEN} Saved to /output/waybackurls.txt")
    

async def certsh(site: str) -> str:
    if "https://" in site:
        site = site.replace("https://", "")
    if "http://" in site:
        site = site.replace("http://", "")
    subdomainpath = os.path.abspath(os.getcwd())
    cmd = f"bash {subdomainpath}/utils/subdomainscanners/certsh.sh {site}"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, err = p.communicate()
    out = out.decode()
    with open("output/subdomains.txt", "w") as f:
        f.writelines(out)
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Subdomains: {Fore.GREEN} Saved to /output/subdomains.txt")

async def rapiddns(site: str) -> str:
    if "https://" in site:
        site = site.replace("https://", "")
    if "http://" in site:
        site = site.replace("http://", "")
    subdomainpath = os.path.abspath(os.getcwd())
    cmd = f"bash {subdomainpath}/utils/subdomainscanners/rapiddns.sh {site}"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, err = p.communicate()
    out = out.decode()
    with open("output/subdomains.txt", "w") as f:
        f.writelines(out)       

async def domains(site: str) -> str:
    if "https://" in site:
        site = site.replace("https://", "")
    if "http://" in site:
        site = site.replace("http://", "")
    if "https://www." in site:
        site = site.replace("https://www.", "")
    if "http://www." in site:
        site = site.replace("http://www.", "")
    if ".com" in site:
        site = site.replace(".com", "")
    domainspath = os.path.abspath(os.getcwd())
    cmd = f"bash {domainspath}/utils/scripts/domains.sh {site}"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, err = p.communicate()
    out = out.decode()
    with open("output/domains.txt", "w") as f:
        f.writelines(out)
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Domains: {Fore.GREEN} Saved to /output/domains.txt")