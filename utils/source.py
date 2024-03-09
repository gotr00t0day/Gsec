from colorama import Fore
from bs4 import BeautifulSoup
import requests


requests.packages.urllib3.disable_warnings()

user_agent_ = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
header = {"User-Agent": user_agent_}


def page_source(domain: str) -> str:
    r = requests.get(domain, verify=False, headers=header)
    if r.status_code == 200:
        soup = BeautifulSoup(r.content, 'html.parser')
        with open(f"output/html_source.txt", "w") as f:
            f.write(f"{soup.prettify()}\n\n")