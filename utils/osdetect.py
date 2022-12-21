from colorama import Fore
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import warnings
import warnings
from cryptography.utils import CryptographyDeprecationWarning
with warnings.catch_warnings():
    warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)
    from scapy.all import sr1
    from scapy.layers.inet import IP, ICMP
import scapy


def osdetection_scan(url: str):
    if "https://" in url:
        url = url.replace("https://", "")
    if "http://" in url:
        url = url.replace("http://", "")
    if "https://www." in url:
        url = url.replace("https://www.", "")
    if "http://www." in url:
        url = url.replace("http://www.", "")
    try:
        os = ''
        pack = IP(dst=url)/ICMP()
        resp = sr1(pack, timeout=3, verbose=0)
        if resp:
            if IP in resp:
                ttl = resp.getlayer(IP).ttl
                if ttl <= 64: 
                    os = 'Linux'
                elif ttl == 128:
                    os = 'Windows'
                elif ttl == 255:
                    os = "FreeBSD"
                else:
                    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} OS: {Fore.RED} Not Detected!")
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} OS: {Fore.GREEN} {os}")
    except scapy.error.Scapy_Exception:
        pass
    except PermissionError:
        pass
    except OSError:
        pass