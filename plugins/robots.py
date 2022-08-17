from colorama import Fore
from urllib.request import urlopen
import urllib
import requests
import io

user_agent = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.0.4) Gecko/2008102920 Firefox/3.0.4"
header = {"User-Agent": user_agent}

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
    

