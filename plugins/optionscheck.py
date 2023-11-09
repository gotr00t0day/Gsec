from colorama import Fore
from plugins import agent_list
import requests

user_agent_ = agent_list.get_useragent()
header = {"User-Agent": user_agent_}

def Get_Options(url: str) -> str:
    s = requests.Session()
    r = s.options(f"{url}", verify=False, headers=header)
    allowed = []
    for item, value in r.headers.items():
        if "Allow" in item:
            allowed.append(value)
        else:
            pass
    if allowed:
        allowed = ", ".join(allowed)
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} OPTIONS: {Fore.GREEN}{allowed}")
        methods = []
        if "PUT" not in allowed or "DELETE" not in allowed:
            # Check for HTTP Method Override
            http_method_delete = {"X-HTTP-Method": "DELETE"}
            http_method_put = {"X-HTTP-Method": "PUT"}
            r_method_override = s.get(f"{url}", verify=False, headers=http_method_delete)
            content = r_method_override.text
            if r_method_override.status_code == 200 and "DELETE" in content:
                methods.append("DELETE")
            elif r_method_override.status_code == 405:
                pass
            r_method_put = s.get(f"{url}", verify=False, headers=http_method_put)
            content2 = r_method_put.text
            if r_method_put.status_code == 200 and "PUT" in content2:
                methods.append("PUT")
            elif r_method_put.status_code == 405:
                pass
        if methods:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} HTTP Method Override: {Fore.GREEN}Possible For {Fore.YELLOW}{', '.join(map(str, methods))}")
    else:
        pass
