from colorama import Fore
from plugins import agent_list
from modules import sub_output
import requests
import sys


user_agent_ = agent_list.get_useragent()
header = {"User-Agent": user_agent_}

def Servers_scan(url: str) -> str:
    sessions = requests.Session()
    server_output = []
    r  = sessions.get(url, verify=False, headers=header)
    try:
        if r.status_code == 200:
            for item, value in r.headers.items():
                if item == "Server":
                    server_output.append(value)
        if "Apache" in server_output:
            sub_output.subpro_scan(f"nuclei -u {url} -tags apache -silent")
        if "Nginx" in server_output:
            sub_output.subpro_scan(f"nuclei -u {url} -tags nginx -silent")
        if "IIS" in server_output:
            sub_output.subpro_scan(f"nuclei -u {url} -tags iis -silent")

    except requests.exceptions.InvalidSchema:
        print("Please use https://www.target.com")
    except requests.exceptions.ConnectionError:
        print("Check the target URL and try again\n")
        sys.exit()
    except requests.exceptions.MissingSchema:
        print("Invalid URL, please use http:// or https://")
        sys.exit()
    

