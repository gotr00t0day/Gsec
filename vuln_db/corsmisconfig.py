from colorama import Fore
import requests


def cors_scan(domain: str) -> str:
    header = {'Origin': 'evil.com'}
    r = requests.get(f"{domain}", verify=False, headers=header)
    for keys, values in r.headers.items(): 
        if keys == "Access-Control-Allow-Origin" and keys == "Access-Control-Allow-Crendentials":
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} CorsMisconfigutation: {Fore.YELLOW} Found Access Control heders, testing further....")
            if keys == "Access-Control-Allow-Origin" and values == "evil.com":
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} CorsMisconfigutation: {Fore.YELLOW} POSSIBLE!") 
        else:
            pass