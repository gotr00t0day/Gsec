from bs4 import BeautifulSoup
from colorama import Fore
from plugins import agent_list
from utils import webserver_scanner
import requests
import urllib3
import sys
import ssl
import re
import test

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

user_agent_ = agent_list.get_useragent()
header = {"User-Agent": user_agent_}

def do_requests(url: str, proxy = None) -> str:
    try:
        if proxy is None:
            sessions = requests.Session()      
            res = sessions.get(url, verify=False, headers=header, allow_redirects=True)
            test.get_response(url, res)
        else:
            sessions = requests.Session()      
            proxies = {
                'sock5': "199.229.254.129"
            }
            res = sessions.get(url, verify=False, headers=header, allow_redirects=True, proxies=proxies)
            test.get_response(url, res)

    except requests.exceptions.InvalidSchema:
        print("Please use https://www.target.com")
    except requests.exceptions.ConnectionError:
        print("Check the target URL and try again\n")
        sys.exit()
    except requests.exceptions.MissingSchema:
        print("Invalid URL, please use http:// or https://")
        sys.exit()
    except AttributeError:
        pass
    except ssl.SSLCertVerificationError:
        pass

def get_headers(url: str) -> str:
    sessions = requests.Session()
    server_output = []
    via_output = []
    x_poweredby_output = []
    try:
        res = sessions.get(url, verify=False, headers=header)
        if res.status_code == 200:
            for value, desc in res.headers.items():
                if value == "Server":
                    server_output.append(desc)
                if value  == "Via":
                    via_output.append(desc)
                if value == "X-Powered-By":
                    x_poweredby_output.append(desc)

            if server_output:
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} SERVER: {Fore.GREEN}{', '.join(map(str,server_output))}")
            else:
                pass
            if "Apache" in server_output:
                apache_version = webserver_scanner.apache_version()
                webpage_server =  re.search(r'([\d.]+)', server_output).group(1)
                if webpage_server < apache_version:
                    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Apache {webpage_server}: {Fore.GREEN} Is outdated, current version is {apache_version}")

            if "nginx" in server_output:
                try:
                    nginx_version = webserver_scanner.nginx_version()
                    webpage_server =  re.search(r'([\d.]+)', server_output).group(1)
                    if webpage_server < nginx_version:
                        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} nginx {webpage_server}: {Fore.GREEN} Is outdated, current version is {nginx_version}")
                except TypeError:
                    pass
            if via_output:
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} VIA: {Fore.GREEN}{', '.join(map(str,via_output))}")
            else:
                pass
            if x_poweredby_output:
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} X-Powered-By: {Fore.GREEN}{', '.join(map(str,x_poweredby_output))}")
            
    except requests.exceptions.InvalidSchema:
        print("Please use https://www.target.com")
    except requests.exceptions.ConnectionError:
        pass
    except requests.exceptions.MissingSchema:
        print("Invalid URL, please use http:// or https://")
        sys.exit()
    except ssl.SSLCertVerificationError:
        pass
    except TypeError:
        pass