import asyncio
import time

from request_url import Requesturl  # 确保Requesturl类在requesturl.py中
from resolver import Resolver  # 确保Resolver类在resolver.py中
from url_manager import URLManager  # 确保URLManager类在urlmanager.py中
import logging as log

async def main():
    # 配置日志: 设置级别、格式和输出文件
    log.basicConfig(
        level=log.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filename='app.log',
        filemode='a'
    )

    # 添加控制台日志输出
    console_handler = log.StreamHandler()
    console_handler.setLevel(log.INFO)
    formatter = log.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    log.getLogger('').addHandler(console_handler)

    log.info("主程序启动")
    # 设置初始URL
    start_url = 'http://192.168.0.1'
    # 初始化URLManager，并传入初始URL
    url_manager = URLManager(start_url)
    # 初始化Resolver
    resolver = Resolver(url_manager)
    # 初始化Requesturl，不再传入start_url
    requesturl = Requesturl(resolver, url_manager)

    await requesturl.start_browser()
    # 循环运行，直到URLManager中没有新的URL
    while url_manager.has_new_url():
        new_url = url_manager.get_new_url()
        await requesturl.fetch(new_url)
        time.sleep(1)

    # 关闭浏览器
    await requesturl.close_browser()

    log.info("程序结束，没有更多的URL需要处理。")

if __name__ == "__main__":
    asyncio.run(main())
