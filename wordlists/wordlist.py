import requests

user_agent = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.0.4) Gecko/2008102920 Firefox/3.0.4"
header = {"User-Agent": user_agent}

def wordlist(wordlist: str) -> list:
    with open(wordlist, 'r') as f:
        _wordlist = [x.strip() for x in f.readlines()]
        return _wordlist
