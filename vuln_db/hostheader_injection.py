from colorama import Fore
import requests

def host_header_injection(url: str):
    redirect = ["301", "302", "303", "307", "308"]
    payload = b"google.com" 
    try:
        session = requests.Session()
        header = {"X-Forwarded-Host": "google.com"}
        header2 = {"Host": "google.com"}
        resp = session.get(f"{url}", verify=False, headers=header)
        resp2 = session.get(f"{url}", verify=False, headers=header2)
        resp_content = resp.content
        resp_status = resp.status_code
        resp2_content = resp2.content
        for value, key in resp.headers.items():
            for pos, web in enumerate(url):
                if pos == 0:
                    vuln_domain = []
                    duplicates_none = []  
                    if value == "Location" and key == payload and resp.status_code in redirect:
                        vuln_domain.append(url)
                    if payload in resp_content or key == payload:
                        vuln_domain.append(url)
                else:
                    pass
        for value2, key2 in resp2.headers.items():
            for pos, web in enumerate(url):
                if pos == 0:
                    if payload in resp2_content or key == payload:
                        vuln_domain.append(url)
                else:
                    pass
        if vuln_domain:
            [duplicates_none.append(x) for x in vuln_domain if x not in duplicates_none]
            duplicates_none = ", ".join(duplicates_none)
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Host Header Injection: {Fore.MAGENTA}POSSIBLE DETECTION!")
        else:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Host Header Injection: {Fore.RED}Not Vulnerable")
    except requests.exceptions.TooManyRedirects:
        pass