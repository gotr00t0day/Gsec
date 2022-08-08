from colorama import Fore
import whois

def whois_scan(domain: str) -> str:
    w = whois.whois(domain)
    name_servers = w.name_servers
    registrar = w.registrar
    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Name Servers: {Fore.GREEN}{', '.join(map(str,name_servers))}")
    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Registrar: {Fore.GREEN}{registrar}")