from colorama import Fore
from urllib.request import urlopen
from plugins import agent_list
import urllib
import requests
import io

user_agent_ = agent_list.get_useragent()
header = {"User-Agent": user_agent_}

def robots_scan(domain: str) -> str:
    res = requests.get(f"{domain}/robots.txt", verify=False, headers=header)
    try:
        if res.status_code == 200:
            req = urlopen(f"{domain}/robots.txt", data=None)
            data = io.TextIOWrapper(req, encoding='utf-8')
            with open("output/robots.txt", "w") as f:
                f.writelines(data.read())
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Robots: {Fore.MAGENTA}Content of robots.txt saved to /output")
    except urllib.error.HTTPError:
        pass
    

