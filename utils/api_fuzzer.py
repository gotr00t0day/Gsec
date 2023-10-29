from colorama import Fore
from time import perf_counter
import requests
import threading
import urllib3
import sys

urllib3.disable_warnings()

user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
header = {"User-Agent": user_agent}

banner = f"""

  █████▒    █    ██    ▒███████▒   ▒███████▒   ▓██   ██▓
▓██   ▒     ██  ▓██▒   ▒ ▒ ▒ ▄▀░   ▒ ▒ ▒ ▄▀░    ▒██  ██▒
▒████ ░    ▓██  ▒██░   ░ ▒ ▄▀▒░    ░ ▒ ▄▀▒░      ▒██ ██░
░▓█▒  ░    ▓▓█  ░██░     ▄▀▒   ░     ▄▀▒   ░     ░ ▐██▓░
░▒█░       ▒▒█████▓    ▒███████▒   ▒███████▒     ░ ██▒▓░
 ▒ ░       ░▒▓▒ ▒ ▒    ░▒▒ ▓░▒░▒   ░▒▒ ▓░▒░▒      ██▒▒▒ 
 ░         ░░▒░ ░ ░    ░░▒ ▒ ░ ▒   ░░▒ ▒ ░ ▒    ▓██ ░▒░ 
 ░ ░        ░░░ ░ ░    ░ ░ ░ ░ ░   ░ ░ ░ ░ ░    ▒ ▒ ░░  
              ░          ░ ░         ░ ░        ░ ░     
                       ░           ░            ░ ░    
{Fore.WHITE}Author:  {Fore.CYAN}c0d3ninja
{Fore.WHITE}Version: {Fore.CYAN}v1.0
"""

print(f"{Fore.RED}{banner}")

with open("payloads/api.txt", "r") as f:
    api_list = (x.strip() for x in f.readlines())

def api_fuzzer(domain: str, api: str) -> None:
    try:
        s = requests.Session()
        url = f"{domain}{api}"
        r = s.get(url, headers=header, verify=False)
        if r.status_code == 200:
            print(f"{Fore.GREEN}[+] {Fore.WHITE} - {Fore.MAGENTA}{url}")
        else:
            print(f"{Fore.RED}[-] {Fore.WHITE} - {Fore.MAGENTA}{url}")
    except requests.exceptions.RequestException:
        pass

def main(domain: str) -> None:
    threads = []
    for api in api_list:
        t = threading.Thread(target=api_fuzzer, args=(domain, api))
        t.start()
        threads.append(t)
    for thread in threads:
        thread.join()

if __name__ == "__main__":
    time_before = perf_counter()
    try:
        main(sys.argv[1])
    except (urllib3.exceptions.MaxRetryError, requests.exceptions.RequestException):
        print(f"{Fore.YELLOW}[!] {Fore.WHITE} - Exception occurred during scanning.")
    print(f"{Fore.MAGENTA}Time: {Fore.WHITE}{perf_counter() - time_before}")



