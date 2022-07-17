from builtwith import builtwith
from colorama import Fore
import requests

user_agent = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.0.4) Gecko/2008102920 Firefox/3.0.4"
header = {"User-Agent": user_agent}

def php_ident(url: str) -> str:
    php_index = []
    php_header = []
    php_language = []
    sessions = requests.Session()
    res = sessions.get(url, verify=False, headers=header)
    for value, key in res.headers.items():
        if "X-Powered-By" in value and "PHP" in key:
            php_header.append(f"PHP")
    indexphp = sessions.get(f"{url}/index.php", verify=False, headers=header)
    if indexphp.status_code == 200 and "404" not in indexphp.text:
        php_index.append("index.php")
    try:
        info = builtwith(f"{url}")
        for key, value in info.items():
            if "programming-languages" in key and "PHP" in value:
                php_language.append("PHP")
            else:
                pass
    except UnicodeDecodeError:
        pass
    except AttributeError:
        pass   
    if php_index:
        print(f"{Fore.MAGENTA}False Positive: {Fore.WHITE}Programming Language could be PHP, doing a thorough scan..")
    if php_header or php_language:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Language: {Fore.GREEN}{php_language}")
        php_info = sessions.get(f"{url}/phpinfo", verify=False, headers=header)
        if php_info.status_code == 200 and "404" not in php_info.text:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Found: {Fore.GREEN} {url}/phpinfo.php")
    else:
        pass
    
