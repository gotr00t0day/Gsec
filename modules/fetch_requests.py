from bs4 import BeautifulSoup
from colorama import Fore
from plugins import agent_list
import requests
import urllib3
import sys
import os 

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

user_agent_ = agent_list.get_useragent()
header = {"User-Agent": user_agent_}

def do_requests(url: str) -> str:
    if "http" in url:
        url2 = url.replace("http://", "")
    if "https" in url:
        url2 = url.replace("https://", "")
    response = os.system("ping -c 1 " + url2 + " > /dev/null")
    if response == 0:
        pass
    else:
        sys.exit()
    sessions = requests.Session()
    try:
        res = sessions.get(url, verify=False, headers=header, allow_redirects=True)
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
            pass
        else:
            print(f"{url} {res.status_code}")
    except requests.exceptions.InvalidSchema:
        print("Please use https://www.target.com")
    except requests.exceptions.ConnectionError:
        print("Check the target URL and try again\n")
        sys.exit()
    except requests.exceptions.MissingSchema:
        print("Invalid URL, please use http:// or https://")
        sys.exit()
    except AttributeError:
        pass

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