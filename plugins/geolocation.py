import requests
from colorama import Fore
import json
import socket
import urllib3

def scan_ip(domain: str) -> str:
    if "https://" in domain:
        domain = domain.replace("https://", "")
    if "http://" in domain:
        domain = domain.replace("http://", "")
    if "https://www." in domain:
        domain = domain.replace("https://www.", "")
    if "http://www." in domain:
        domain = domain.replace("http://www.", "")
        
    try:
        ip = socket.gethostbyname(domain)     
        url = f'https://geolocation-db.com/jsonp/{ip}'
        r = requests.get(url)
        result = r.content.decode()
        result = result.split("(")[1].strip(")")
        result  = json.loads(result)
        info = []
        for k,v in result.items():
            if "country_name" in k:
                info.append(v)
            if "city" in k:
                if v is None:
                    pass
                else:
                    info.append(v)
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} GeoLocation: {Fore.GREEN}{', '.join(map(str, info))}")
    except socket.gaierror:
        pass
    except UnicodeError:
        pass
    except requests.exceptions.ConnectTimeout:
        pass
    except requests.exceptions.ConnectionError:
        pass
    except requests.exceptions.ReadTimeout:
        pass
    except requests.exceptions.ChunkedEncodingError:
        pass
    except requests.exceptions.Timeout:
        pass
    except urllib3.exceptions.ConnectTimeoutError:
        pass
    except urllib3.exceptions.MaxRetryError:
        pass