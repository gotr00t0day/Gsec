from colorama import Fore
from time import perf_counter
import requests
import threading
import urllib3
import os

urllib3.disable_warnings()

user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
header = {"User-Agent": user_agent}

dir = os.getcwd()
print(dir)
with open(f"{dir}/utils/payloads/api.txt", "r") as f:
    api_list = (x.strip() for x in f.readlines())

def api_fuzzer(domain: str, api: str) -> None:
    apis = []
    try:
        s = requests.Session()
        url = f"{domain}{api}"
        r = s.get(url, headers=header, verify=False)
        if r.status_code == 200:
            apis.append(url)
            print(f"{Fore.GREEN}[+] {Fore.WHITE} - {Fore.MAGENTA}{', '.join(map(str,apis))}")
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


