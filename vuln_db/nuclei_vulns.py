from colorama import Fore
from modules import scan, sub_output
import requests


def nuclei_nginx_scan(url: str) -> str:
    sessions = requests.Session()
    res = sessions.get(f"{url}", verify=False)
    for item, value in res.headers.items():
        if "nginx" in value:
            scan.commands(f"nuclei -u {url} -t ~/nuclei-templates/misconfiguration/nginx/ -silent")

def nuclei_cve_scan(domain: str) -> str:
    sub_output.subpro_scan(f"nuclei -u {domain} -tags cve -severity critical,high -silent")
    sub_output.subpro_scan(f"nuclei -u {domain} -t cves/ -silent")

def nuclei_fuzzing_scan(domain: str) -> str:
    sub_output.subpro_scan(f"nuclei -t ~/nuclei-templates/fuzzing/ -u {domain} -silent")

def nuclei_ultimate_scan(domain: str) -> str:
    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.WHITE}Task{Fore.CYAN}:{Fore.LIGHTBLUE_EX} CVE{Fore.WHITE} Status: {Fore.GREEN}Running...")
    sub_output.subpro_scan(f"nuclei -u {domain} -tags cve -severity critical,high -silent")
    sub_output.subpro_scan(f"nuclei -u {domain} -tags cve -silent")
    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.WHITE}Task{Fore.CYAN}:{Fore.LIGHTBLUE_EX} CVE{Fore.WHITE} Status: {Fore.GREEN}DONE!\n")
    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.WHITE}Task{Fore.CYAN}:{Fore.LIGHTBLUE_EX} Vulnerabilities{Fore.WHITE} Status: {Fore.GREEN}Running...")
    sub_output.subpro_scan(f"nuclei -u {domain} -t vulnerabilities/ -severity critical,high -silent")
    sub_output.subpro_scan(f"nuclei -u {domain} -t vulnerabilities/ -silent")
    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.WHITE}Task{Fore.CYAN}:{Fore.LIGHTBLUE_EX} Vulnerabilities{Fore.WHITE} Status: {Fore.GREEN}DONE!\n")
    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.WHITE}Task{Fore.CYAN}:{Fore.LIGHTBLUE_EX} Misconfigurations{Fore.WHITE} Status: {Fore.GREEN}Running...")
    sub_output.subpro_scan(f"nuclei -u {domain} -t misconfiguration/ -severity critical,high -silent")
    sub_output.subpro_scan(f"nuclei -u {domain} -t misconfiguration/ -silent")
    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.WHITE}Task{Fore.CYAN}:{Fore.LIGHTBLUE_EX} Misconfiguration{Fore.WHITE} Status: {Fore.GREEN}DONE!\n")
    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.WHITE}Status: {Fore.GREEN}All Tasks done!!")