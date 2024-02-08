from colorama import Fore
import requests
import concurrent.futures

target = "google.com"

def check_redirect(url, target):
    response = requests.get(url, allow_redirects=False)
    if response.status_code in [301, 302, 303, 307, 308]:
        location = response.headers.get("Location")
        if location and target in location:
            return url
    return None

def scan(url: str):
    base_url = url.rstrip("/")
    with open("utils/payloads/paths.txt", "r") as f:
        paths = [x.strip() for x in f.readlines()]
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(check_redirect, f"{base_url}{path}", target) for path in paths]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Open redirect found: {Fore.MAGENTA}{result}")
