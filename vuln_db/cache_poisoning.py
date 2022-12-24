from plugins import agent_list
from colorama import Fore
import requests

user_agent_ = agent_list.get_useragent()
header = {"User-Agent": user_agent_, "X-Forawarded-Scheme": "http"}


def cache_dos_scan(url: str) -> str:
    sessions = requests.Session()
    r = sessions.get(url, verify=False, headers=header)
    if r.status_code == 301:
        for key, description in r.headers.items():
            if "Location" in key and url in description:
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Cache Poisoning: {Fore.GREEN}POSSIBLE!")