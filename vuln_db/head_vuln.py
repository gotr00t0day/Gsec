from plugins import agent_list
from colorama import Fore
from utils import logins
import requests
import concurrent.futures

user_agent_ = agent_list.get_useragent()
header = {"User-Agent": user_agent_}

login_list = logins.login_list()

def head_auth_bypass(url: str) -> str:
    options = []
    r = requests.options(url, verify=False, headers=header)
    for item, value in r.headers.items():
        if "Allow" in item:
            options.append(value)
    if "HEAD" in options:
        found_link = []
        login_paths = [x.strip() for x in login_list ]
        for login_links in login_paths:
            r2 = requests.head(f"{url}/{login_links}", verify=False, headers=header)
            if r2.status_code == 200:
                options.append(f"{url}/{login_links}")
        if found_link:
           print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Potential Auth Bypass: {Fore.GREEN}{', '.join(map(str,found_link))}") 
        
if __name__=='__main__':
    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(head_auth_bypass, login_list)
