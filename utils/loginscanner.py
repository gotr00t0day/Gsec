from colorama import Fore
from utils import logins
from plugins import agent_list
import requests, urllib3
import concurrent.futures

adminlist = logins.login_list()

user_agent_ = agent_list.get_useragent()
header = {"User-Agent": user_agent_}

def admin_list(url: str) -> str:
    try:
        found_adminlinks = []
        admin_paths = [x.strip() for x in adminlist]
        for admin_links in admin_paths:
            links = f"{url}/{admin_links}"
            r =  requests.get(links, verify=False)
            if r.status_code == 200:
                found_adminlinks.append(links)
        if found_adminlinks:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Login: {Fore.GREEN} {', '.join(map(str,found_adminlinks))}") 
            options = []
            r1 = requests.options(url, verify=False, headers=header)
            for item, value in r1.headers.items():
                if "Allow" in item:
                    options.append(value)
            if "HEAD" in options:
                found_link = []
                login_paths = [x.strip() for x in adminlist ]
                for login_links in login_paths:
                    r2 = requests.head(f"{url}/{login_links}", verify=False, headers=header)
                    if r2.status_code == 200:
                        options.append(f"{url}/{login_links}")
                if found_link:
                    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Potential Auth Bypass: {Fore.GREEN}{', '.join(map(str,found_link))}") 
        
    except requests.exceptions.MissingSchema:
        print (Fore.RED + "Please use http:// or https://")
        pass
    except urllib3.exceptions.ProtocolError:
        pass
    except requests.exceptions.ConnectionError:
        pass




if __name__=='__main__':
    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(admin_list, adminlist)