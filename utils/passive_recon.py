from colorama import Fore
import whois
import dns.resolver

def whois_scan(domain: str) -> str:
    w = whois.whois(domain)
    name_servers = w.name_servers
    registrar = w.registrar
    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Name Servers: {Fore.GREEN}{', '.join(map(str,name_servers))}")
    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Registrar: {Fore.GREEN}{registrar}")

def dns_info(domain: str) -> str:
    if "https://" in domain:
        domain = domain.replace("https://", "")
    if "http://" in domain:
        domain = domain.replace("http://", "")
    mail_exchange = dns.resolver.resolve(domain, "MX")
    for mail_info in mail_exchange:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} MX: {Fore.GREEN}{mail_info.to_text()}")