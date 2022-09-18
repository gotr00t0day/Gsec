from colorama import Fore, Back, Style
from plugins import agent_list
import concurrent.futures
import requests
import argparse
import sys

user_agent_ = agent_list.get_useragent()
header = {"User-Agent": user_agent_}

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()

group.add_argument('-w', '--wordlist', action='store',
                   type=str, help='wordlist to use',
                   metavar='wordlist.txt')

parser.add_argument('-e', '--extension', action='store',
                   type=str, help='files to search for',
                   metavar='.html')

parser.add_argument('-d', '--domain', action='store',
                    help="domain to check",
                    metavar="https://domain.com")

args = parser.parse_args()


try:
    with open(f"{args.wordlist}", "r") as f:
        wordlist = (x.strip() for x in f.readlines())
except FileNotFoundError:
    print(f"{Fore.RED} FILE {args.wordlist} NOT FOUND")
    sys.exit(0)


def get_request(url: str):
    response = requests.get(url, headers=header)
    if response.status_code == 200:
        print(f'{Fore.GREEN} Found: {url}')
    else:
        print(Fore.RED + f"{url}")

def run_main(wordlist):
    link =  f"{args.domain}/{wordlist}"
    if "#" in wordlist:
        pass
    else:
        if args.domain:
            if args.wordlist:
                if args.extension:
                    extensions = f"{args.domain}/{wordlist}.{args.extension}"
                    wordlist
                    get_request(extensions)
                else:
                    wordlist
                    get_request(link)

                 
if __name__ == "__main__":
    try:
        print(Style.RESET_ALL)
        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor.map(run_main, wordlist)
    except KeyboardInterrupt as err:
        sys.exit(0)
    except Exception as e:
        print(e)

