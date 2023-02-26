from colorama import Fore
from modules import urltoip 
import socket
import threading

open_ports = []
closed_ports = []
start_port = 1
end_port = 65000

# specify the range of ports to scan

# define a function to scan a single port and print the service banner
def scan_port(port):
    try:
        # create a TCP socket and attempt to connect to the specified port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip_address, port))
        
        # if the connection is successful, attempt to receive the service banner
        if result == 0:
            open_ports.append(f"{port}")
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} PORTS: {Fore.GREEN}{', '.join(map(str,open_ports))}")
        
        # close the socket
        sock.close()
    except:
        pass

# create a list of threads to scan each port in the range
def main(domain: str):
    global ip_address
    ip_address = urltoip.get_ip(domain)
    threads = []
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(port,))
        threads.append(thread)
        thread.start()

    # wait for all threads to complete
    for thread in threads:
        thread.join()
