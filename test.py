from bs4 import BeautifulSoup
from colorama import Fore
import sys


def get_response(url, res):
        if res.status_code == 200:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} {url} {Fore.GREEN}200")
        elif res.status_code == 403:
            soup = BeautifulSoup(res.text, 'html.parser')
            title = soup.find("title")
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} {url} {Fore.RED} Forbidden ({title.get_text()})")
        elif res.status_code == 404:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} {url} {Fore.RED} 404")
            print(f"{Fore.RED} EXITING!!")
            sys.exit()
        elif res.history == 301 or 302:
            location = []
            for key, desc in res.headers.items():
                if "Location" in key or "location" in key:
                    location.append(desc)
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} {url} {Fore.RED} seems to be redirecting to {Fore.CYAN}{res.url}")
        else:
            print(f"{url} {res.status_code}")