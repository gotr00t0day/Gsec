from bs4 import BeautifulSoup
from colorama import Fore
import requests
import urllib3
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

user_agent = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.0.4) Gecko/2008102920 Firefox/3.0.4"
header = {"User-Agent": user_agent}

def do_requests(url: str) -> str:
    sessions = requests.Session()
    try:
        res = sessions.get(url, verify=False, headers=header)
        if res.status_code == 200:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} {url} {Fore.GREEN}200")
        elif res.status_code == 403:
            soup = BeautifulSoup(res.text, 'html.parser')
            title = soup.find_all("title")
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} {url} {Fore.RED} Forbidden ({title.get_text()})")
        elif res.status_code == 404:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} {url} {Fore.RED} 404")
            print(f"{Fore.RED} EXITING!!")
            sys.exit()
        elif res.history == 301 or 302:
            location = []
            for key, desc in res.headers.items():
                if key == "Location" or "location":
                    location.append(desc)
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} {url} {Fore.RED} seems to be redirecting to {location}")
            pass
        else:
            print(f"{url} {res.status_code}")
    except requests.exceptions.InvalidSchema:
        print("Please use https://www.target.com")
    except requests.exceptions.ConnectionError:
        print("Check the target URL and try again\n")
        pass
    except requests.exceptions.MissingSchema:
        print("Invalid URL, please use http:// or https://")
        sys.exit()

def get_headers(url: str) -> str:
    sessions = requests.Session()
    server_output = []
    via_output = []
    try:
        res = sessions.get(url, verify=False, headers=header)
        if res.status_code == 200:
            for value, desc in res.headers.items():
                if value == "Server":
                    server_output.append(desc)
                if value  == "Via":
                    via_output.append(desc)
            if server_output:
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} SERVER: {Fore.GREEN}{', '.join(map(str,server_output))}")
            else:
                pass
            if via_output:
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} VIA: {Fore.GREEN}{', '.join(map(str,via_output))}")
            else:
                pass
            
    except requests.exceptions.InvalidSchema:
        print("Please use https://www.target.com")
    except requests.exceptions.ConnectionError:
        print("Check the target URL and try again\n")
        sys.exit()
    except requests.exceptions.MissingSchema:
        print("Invalid URL, please use http:// or https://")
        sys.exit()