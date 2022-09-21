from colorama import Fore
from plugins import agent_list
import requests

user_agent_ = agent_list.get_useragent()
header = {"User-Agent": user_agent_}

def Get_Options(url: str) -> str:
    r = requests.options(f"{url}", verify=False, headers=header)
    for item, value in r.headers.items():
        if "Allow" in item:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} OPTIONS: {Fore.GREEN}{value}")
        else:
            pass