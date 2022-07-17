from colorama import Fore
import http.client
import socket
import time

def Get_Options(url: str) -> str:
    try:
        if "https://" in url:
            url = url.replace("https://", "")
        if "http://" in url:
            url = url.replace("http://", "")
        conn = http.client.HTTPConnection(url)
        conn.connect()
        conn.request('OPTIONS', '/')
        response = conn.getresponse()
        check = response.getheader('allow')
        if check is None:
            pass
            conn.close()
        else:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} OPTIONS: {Fore.GREEN}{check}")
    except socket.gaierror:
        pass
        time.sleep(2)
    except http.client.InvalidURL:
        print (Fore.RED + "Please use: site.com or www.site.com")
    except ValueError:
        print(Fore.RED + "Enter valid port")