from colorama import Fore
import requests
import os

requests.packages.urllib3.disable_warnings()

user_agent_ = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
header = {"User-Agent": user_agent_}

directory = os.getcwd()

def get_headers(domain: str):
    sessions = requests.Session()
    r = sessions.get(domain, verify=False, headers=header)
    with open(f"{directory}/output/headers.txt", "w") as f:
            for item, value in r.headers.items():
                 f.writelines(f"{item}: {value}\n")