from colorama import Fore
from plugins import agent_list
import requests

user_a = agent_list.get_useragent()
header = {"User-Agent": user_a}

def sitemap(domain: str) -> str:
    sitemap_loc = ["sitemap.txt", "sitemap.xml", "sitemap-index.xml", "sitemap/sitemap.xml"]
    for sitemap_locs in sitemap_loc:
        s = requests.Session()
        r = s.get(f"{domain}/{sitemap_locs}", verify=False, headers=header)
        if r.status_code == 200:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Sitemap: {Fore.GREEN}{domain}/{sitemap_locs}")
        else:
            pass