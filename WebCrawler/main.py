import asyncio
import time

from request_url import Requesturl  
from resolver import Resolver  
from url_manager import URLManager  
import logging as log

async def main():
    log.basicConfig(
        level=log.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filename='app.log',
        filemode='a'
    )

    console_handler = log.StreamHandler()
    console_handler.setLevel(log.INFO)
    formatter = log.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    log.getLogger('').addHandler(console_handler)

    log.info("Start")
    start_url = 'http://192.168.0.1'
    url_manager = URLManager(start_url)
    resolver = Resolver(url_manager)
    requesturl = Requesturl(resolver, url_manager)

    await requesturl.start_browser()
    while url_manager.has_new_url():
        new_url = url_manager.get_new_url()
        await requesturl.fetch(new_url)
        time.sleep(1)

    await requesturl.close_browser()

    log.info("End")

if __name__ == "__main__":
    asyncio.run(main())
