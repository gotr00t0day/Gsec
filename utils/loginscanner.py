from utils import logins
from plugins import agent_list
from colorama import Fore
import asyncio



adminlist = logins.login_list()

user_agent_ = agent_list.get_useragent()
header = {"User-Agent": user_agent_}

async def get_responses(client, link_paths: str):
    try:
        found_adminlinks = []
        r = await client.get(link_paths)
        if r.status_code == 200 and "404" not in r.text and "Page Not Found" not in r.text:
            found_adminlinks.append(link_paths + "\n")
        with open("output/loginpages.txt") as f:
            f.writelines(found_adminlinks)
    except RuntimeError:
        pass
    except ValueError:
        pass


async def main(url: str):
    try:
        async with httpx.AsyncClient(verify=False, headers=header) as client:
            task = []
            admin_paths = [x.strip() for x in adminlist]
            for admin_links in admin_paths:
                links = f"{url}/{admin_links}"
                task.append(asyncio.create_task(get_responses(client, links)))
            await asyncio.gather(*task)
            return task
    except RuntimeError:
        pass


if __name__=='__main__':
    asyncio.run(main())
