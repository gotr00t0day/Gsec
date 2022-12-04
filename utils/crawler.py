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
    link_list = []
    for page_links in links:
        page_links = urljoin(url, page_links)
        link_list.append(page_links + "\n")
        with open("output/spider.txt", "w") as f:
            f.writelines(link_list)