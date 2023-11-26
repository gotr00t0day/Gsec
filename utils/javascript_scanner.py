from modules import sub_output
from colorama import Fore
import os


def spider(domain: str):
    directory = os.getcwd()
    sub_output.subpro_scan(f"echo {domain} | waybackurls | grep '\\.js$' | uniq >> {directory}/output/javascript")
    sub_output.subpro_scan(f"echo {domain} | gau | grep -Eo 'https?://\\S+?\\.js' | uniq >>{directory}/output/javascript")
    with open(f"{directory}/output/javascript", "r") as f:
        lines = [x.strip() for x in f.readlines()]
        if lines:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} JavaScript files: {Fore.GREEN}{len(lines)}") 