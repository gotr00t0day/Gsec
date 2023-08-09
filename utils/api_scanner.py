from colorama import Fore
import requests


def swagger_ui(target: str) -> str:
    with open("utils/payloads/swaggerui.txt", "r") as f:
        swagger_endpoints = [x.strip() for x in f.readlines()]
        endpoint_list = []
        for endpoints in swagger_endpoints:
            s = requests.Session()
            r = s.get(f"{target}{endpoints}", verify=False)
            if r.status_code == 200:
                endpoint_list.append(endpoints)
        if endpoint_list:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Swagger-ui: {Fore.GREEN}{Fore.GREEN}{', '.join(map(str,endpoint_list))}")
        