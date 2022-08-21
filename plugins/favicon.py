from colorama import Fore
import requests
import codecs
import mmh3

def favicon_hash(domain: str) -> str:
    response = requests.get(f'{domain}/favicon.ico', verify=False)
    if response.status_code == 200:
        favicon = codecs.encode(response.content,"base64")
        hash = mmh3.hash(favicon)
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} FavIcon Hash: {Fore.MAGENTA}{hash} {Fore.YELLOW} - ( Shodan Dork: org:'Target' http.favicon.hash:{hash} to find new assets / IPs ) ")