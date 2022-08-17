from colorama import Fore
import requests
import concurrent.futures
import sys
import os

target = sys.argv[0]

with open(f"{os.path.abspath(os.getcwd())}/wordlists/subdomains-5000.txt", "r") as f:
    wordlist = [x.strip() for x in f.readlines()]    


user_agent = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.0.4) Gecko/2008102920 Firefox/3.0.4"
header = {"User-Agent": user_agent}

def main(wordlist: str):
        subdomains = []
        if "https://www." in target:
            target = target.replace("https://www.", "")
        if "http://www." in target:
            target = target.replace("http://www.", "")
        for subdomain_list in wordlist:
            r = requests.get(f"{subdomain_list}.{target}", verify=False, headers=header)
            if r.status_code == 200:
                if "admin" or "stage" or "dev" or "api" or "staging" or "test" or "beta" in subdomain_list:
                    subdomains.append(subdomain_list)
        if subdomains:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Interesting subdomains: {Fore.GREEN}{Fore.GREEN}{', '.join(map(str,subdomains))}")


if __name__ == "__main__":
    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor.map(main, wordlist)
    except KeyboardInterrupt as err:
      sys.exit(0)

