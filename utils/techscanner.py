from builtwith import builtwith
from colorama import Fore

def Tech(url: str) -> str:
    tech = []
    desc = []
    total = []
    try:
        info = builtwith(f"{url}")
        for key, value in info.items():
           tech.append(key)
           desc.append(value)
        for tech, desc in zip(tech, desc):
            total.append(f"{tech}:{desc}")
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Technologies: {Fore.GREEN}{', '.join(map(str,total))}")
    except UnicodeDecodeError:
        pass
    except AttributeError:
        pass