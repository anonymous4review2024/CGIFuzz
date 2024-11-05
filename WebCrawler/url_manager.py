import logging as log
from urllib.parse import urlparse

class URLManager:
    def __init__(self, start_url):
        log.info("URLManager start")
        self.ip = None
        self.new_urls = set()
        self.old_urls = set()
        self.add_new_url(start_url)  

    def format_url(self, url):
        if not self.ip:
            self.ip = urlparse(url).hostname
        else:
            if urlparse(url).hostname != self.ip:
                return False
        return url.split('?')[0]

    def add_new_url(self, url):
        url=self.format_url(url)
        if url:
            log.info(f"Adding new URL: {url}")
            if url is None:
                return
            if url not in self.new_urls and url not in self.old_urls:
                self.new_urls.add(url)

    def add_new_urls(self, urls):
        log.info(f"Adding new URLs: {urls}")
        if urls is None or len(urls) == 0:
            return
        for url in urls:
            self.add_new_url(url)

    def has_new_url(self):
        return len(self.new_urls) != 0

    def get_new_url(self):
        new_url = self.new_urls.pop()  
        self.old_urls.add(new_url)
        log.info(f"New URL: {new_url}")
        return new_url
