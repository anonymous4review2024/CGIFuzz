import logging as log
from urllib.parse import urlparse

class URLManager:
    def __init__(self, start_url):
        """
        初始化URLManager类，并将初始URL加入管理器
        :param start_url: 初始URL字符串
        """
        log.info("URLManager start")
        self.ip = None
        self.new_urls = set()
        self.old_urls = set()
        self.add_new_url(start_url)  # 将初始URL添加到新URL集合中

    def format_url(self, url):
        if not self.ip:
            self.ip = urlparse(url).hostname
        else:
            if urlparse(url).hostname != self.ip:
                return False
        return url.split('?')[0]

    def add_new_url(self, url):
        """
        向管理器中添加一个新的URL
        :param url: 单个URL字符串
        """
        url=self.format_url(url)
        if url:
            log.info(f"Adding new URL: {url}")
            if url is None:
                return
            if url not in self.new_urls and url not in self.old_urls:
                self.new_urls.add(url)

    def add_new_urls(self, urls):
        """
        向管理器中添加批量新的URLs
        :param urls: URL列表
        """
        log.info(f"Adding new URLs: {urls}")
        if urls is None or len(urls) == 0:
            return
        for url in urls:
            self.add_new_url(url)

    def has_new_url(self):
        """
        判断是否还有未爬取的URL
        :return: 布尔值，表示是否还有未爬取的URL
        """
        return len(self.new_urls) != 0

    def get_new_url(self):
        """
        获取一个未爬取的URL，并将其从未爬取的集合中移动到已爬取的集合
        :return: 一个未爬取的URL
        """
        new_url = self.new_urls.pop()  # 移除并返回一个URL
        self.old_urls.add(new_url)
        log.info(f"New URL: {new_url}")
        return new_url
