from urllib.parse import urljoin
import requests
import re


user_agent_ = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
header = {"User-Agent": user_agent_}

def scan(url: str) -> str:
    s = requests.Session()
    r = s.get(url, verify=False, headers=header)
    content = r.content
    links = re.findall('(?:href=")(.*?)"', content.decode('utf-8'))
    duplicate_links = set(links)
    links_l = []
    for page_links in links:
        page_links = urljoin(url, page_links)
        if page_links not in duplicate_links:
            links_l.append(page_links)
    for link in links_l:
        try:
            with open("output/spider.txt", "w") as f:
                f.writelines(link)
        except PermissionError:
            pass
        