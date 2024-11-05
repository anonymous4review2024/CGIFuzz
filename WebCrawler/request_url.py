from playwright.async_api import async_playwright
import logging as log
import os

class Requesturl:
    def __init__(self, resolver, url_manager):
        log.info("Initializing Requesturl")
        self.resolver = resolver
        self.url_manager = url_manager
        self.browser = None
        self.playwright = None
        self.page = None


    async def start_browser(self):
        log.info("Starting browser...")
        if not self.playwright:
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(headless=False)
            self.page = await self.browser.new_page()

    async def fetch(self, url):
        log.info(f"Fetching {url}")
        if not self.browser:
            log.debug(f"Browser not open try reopen")
            await self.start_browser()  
            self.page = await self.browser.new_page()


        # page = await self.browser.new_page()
        try:
            await self.page.goto(url)
            await self.resolver.parse_html(self.page)
        except Exception as e:
            print(f"Error fetching {url}: {str(e)}")
        # finally:
        #     await page.close()  

    async def close_browser(self):
        log.info("Closing browser")
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
