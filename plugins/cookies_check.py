from colorama import Fore
import requests
import base64
import binascii

user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
header = {"User-Agent": user_agent}

"""
 ██▓███   ██░ ██  ██▓███    ██████ ▓█████   ██████   ██████  ██▓▓█████▄ 
▓██░  ██▒▓██░ ██▒▓██░  ██▒▒██    ▒ ▓█   ▀ ▒██    ▒ ▒██    ▒ ▓██▒▒██▀ ██▌
▓██░ ██▓▒▒██▀▀██░▓██░ ██▓▒░ ▓██▄   ▒███   ░ ▓██▄   ░ ▓██▄   ▒██▒░██   █▌
▒██▄█▓▒ ▒░▓█ ░██ ▒██▄█▓▒ ▒  ▒   ██▒▒▓█  ▄   ▒   ██▒  ▒   ██▒░██░░▓█▄   ▌
▒██▒ ░  ░░▓█▒░██▓▒██▒ ░  ░▒██████▒▒░▒████▒▒██████▒▒▒██████▒▒░██░░▒████▓ 
▒▓▒░ ░  ░ ▒ ░░▒░▒▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░░░ ▒░ ░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░░▓   ▒▒▓  ▒ 
░▒ ░      ▒ ░▒░ ░░▒ ░     ░ ░▒  ░ ░ ░ ░  ░░ ░▒  ░ ░░ ░▒  ░ ░ ▒ ░ ░ ▒  ▒ 
░░        ░  ░░ ░░░       ░  ░  ░     ░   ░  ░  ░  ░  ░  ░   ▒ ░ ░ ░  ░ 
          ░  ░  ░               ░     ░  ░      ░        ░   ░     ░    
                                                                 ░  

"""

def phpsessid_session(url: str) -> str:
    try:
        r = requests.get(url, verify=False, headers=header)
        for k, v in r.headers.items():
            if "Cookie" in k and "PHPSESSID" in v:
                phpsessid_cookie = v
                cookie = phpsessid_cookie.split()[0]
                base64_cookie = cookie.split("=")[1]
                decode = base64.b64decode(base64_cookie)
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} PHPSESSID: {Fore.GREEN}{decode}")
    except binascii.Error:
        pass