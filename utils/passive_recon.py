from colorama import Fore
import whois
import dns.resolver
import shodan
import socket
import subprocess

def commands(cmd):
    try:
        subprocess.check_call(cmd, shell=True)
    except:
        pass


def whois_scan(domain: str) -> str:
    w = whois.whois(domain)
    name_servers = w.name_servers
    registrar = w.registrar
    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Name Servers: {Fore.GREEN}{', '.join(map(str,name_servers))}")
    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Registrar: {Fore.GREEN}{registrar}")

def dns_info(domain: str) -> str:
    mx = []
    if "https://" in domain:
        domain = domain.replace("https://", "")
        if "www." in domain:
            domain = domain.replace("www.", "")
    if "http://" in domain:
        domain = domain.replace("http://", "")
        if "www." in domain:
            domain = domain.replace("www.", "")

    mail_exchange = dns.resolver.resolve(domain, "MX")
    soa = dns.resolver.resolve(domain, "SOA")
    for mail_info in mail_exchange:
        mx.append(mail_info.to_text())
    for state_of_authority in soa:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} SOA: {Fore.GREEN}{state_of_authority.to_text()}")
    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} MX: {Fore.GREEN}{', '.join(map(str,mx))}")

def shodan_search(domain: str) -> str:
    with open(f"core/.shodan", "r") as f:
        key = f.readlines()
        api = shodan.Shodan(key)
        try:
            results = api.search(domain)
            results_ = []
            results_5 = []
            for result in results['matches']:
                results_.append(result['ip_str'])
            results_5.append(results_[0:9])
            print(results_5)
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Shodan IPs: {Fore.GREEN}{', '.join(map(str,results_5))}")
        except shodan.APIError:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.YELLOW} Shodan Key: {Fore.GREEN} Invalid Key")
        except socket.herror:
            pass

def waybackurls_scan(domain: str) -> str:
    cmd = f"waybackpy --url {domain} --user_agent 'my-user-agent' --known_urls | head -10000"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    check, err = p.communicate()
    check = check.decode()
    with open("output/waybackurls.txt", "a") as f:
        f.writelines(check)
    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Waybackurls: {Fore.GREEN} Saved to /output/waybackurls.txt")
    



