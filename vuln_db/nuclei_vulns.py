from colorama import Fore
from modules import sub_output


def nuclei_cve_scan(domain: str) -> str:
    sub_output.subpro_scan(f"nuclei -u {domain} -t cves/ -severity medium,high,critical -silent")
    sub_output.subpro_scan(f"nuclei -u {domain} -t vulnerabilities/ -severity medium,high,critical -silent")


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