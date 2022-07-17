from colorama import Fore
import threading
import socket
from modules import urltoip 
import ipaddress

ports = [80, 8080, 443]

def portscanner(domain: str):
    ip = urltoip.get_ip(domain)
    open_ports = []
    try:
        for port in ports:
            sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            data = sck.connect_ex((ip, port))
            if data == 0:
                open_ports.append(f"{port}")
                sck.close()
            else:
                pass
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

if __name__=="__main__":
    t1 = threading.Thread(target=portscanner, args=(ports,))
    t1.start()