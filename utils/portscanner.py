from colorama import Fore
import socket
from modules import urltoip
import ipaddress
import concurrent.futures

ports = [80, 8080, 443, 8443]

def portscanner(domain: str):
    ip = urltoip.get_ip(domain)
    open_ports = []
    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(check_port, ip, port) for port in ports]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} PORTS: {Fore.GREEN}{', '.join(map(str,open_ports))}")
    except socket.error:
        print (Fore.RED + "Could not connect to host")
        pass
    except KeyboardInterrupt:
        print ("You pressed CTRL+C")
    except ipaddress.AddressValueError:
        print ("IP address not allowed")
    except TypeError:
        pass

def check_port(ip, port):
    sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data = sck.connect_ex((ip, port))
    if data == 0:
        return port
