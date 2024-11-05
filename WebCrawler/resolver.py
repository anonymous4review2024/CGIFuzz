import json
import os
import asyncio
import time
from datetime import datetime
from urllib.parse import urljoin

import aiohttp
from playwright.async_api import async_playwright
from playwright.async_api import Page
import logging as log
from urllib.parse import urlparse


class Resolver:
    def __init__(self, url_manager):
        """
        初始化Resolver
        :param url_manager: URLManager实例，用于管理URL
        """
        log.info("Resolver init")
        self.url_manager = url_manager
        self.username = "admin"
        self.password = "admin"
        self.api_key = "sk-3EukPVUuMm6y4hCXBD55Zo3qZ1F2hjxLneJ2TAKk4PGKDFVq"
        self.cookies = []  # 用于存储登录后获取的cookie

    async def find_field(self, page: Page, selectors):
        """
        在给定的选择器列表中查找可用的输入字段。

        :param page: Playwright的Page对象
        :param selectors: 输入字段的选择器列表
        :return: 第一个找到的可用字段的选择器，如果没有找到则返回None
        """
        for selector in selectors:
            field = await page.query_selector(selector)
            if field:
                return selector
        return None


    async def authcheck(self, page: Page):
        """
        检查给定的页面是否是登录页面，并返回用户名和密码输入框的选择器。

        :param page: Playwright的Page对象
        :return: 用户名和密码输入框的选择器或None
        """
        log.info("authcheck start")
        url_keywords = ["sign-in", "login", "signin", "auth"]
        if not any(keyword in page.url.lower() for keyword in url_keywords):
            return None, None

        # 定义可能的输入字段选择器
        username_selectors = ["input[name='username']", "input[name='name']", "input[name='user']", "input[name='email']"]
        password_selectors = ["input[name='password']", "input[name='passwd']"]

        # 查找并验证用户名和密码输入框
        username_field_selector = await self.find_field(page, username_selectors)
        password_field_selector = await self.find_field(page, password_selectors)

        if username_field_selector and password_field_selector:
            log.info(f"authcheck success, this is a auth page")
            return username_field_selector, password_field_selector
        return None, None

    async def login(self, page: Page, username_selector: str, password_selector: str) -> bool:
        """
        在指定的输入框中填写登录信息。

        :param page: Playwright的Page对象
        :param username_selector: 用户名输入框的选择器
        :param password_selector: 密码输入框的选择器
        :return: 如果填写登录信息成功，则返回True，否则返回False
        """
        log.info("Logging in...")
        # 检查用户名输入框是否可写
        username_field = await page.query_selector(username_selector)
        if username_field and await username_field.is_visible() and await username_field.get_attribute('type') != 'hidden':
            await username_field.fill(self.username)

        # 检查密码输入框是否可写
        password_field = await page.query_selector(password_selector)
        if password_field and await password_field.is_visible() and await password_field.get_attribute('type') != 'hidden':
            await password_field.fill(self.password)

        login_button_selectors = [
            "text='Login'",
            "text='登录'",
            "text='Sign in'",
            "text='提交'",
            "button[type='submit']",
            "input[type='submit']",
            "#loginButton",
            ".login-button"
        ]
        for selector in login_button_selectors:
            login_button = await page.query_selector(selector)
            if login_button and await login_button.is_visible():
                await login_button.click()
                # 等待页面导航作为登录成功的一个指标
                await page.wait_for_load_state('networkidle')
                # 登录成功后获取cookie
                self.cookies = await page.context.cookies()
                return True  # 登录按钮被找到并点击
        return False  # 未找到登录按钮

    async def apply_cookies(self, page: Page):
        """
        在新页面中应用已保存的cookie。

        :param page: Playwright的Page对象
        """
        # await page.context.add_cookies(self.cookies)

    async def handle_radio(self, input_element):
        # 检查单选按钮是否可见且未被选中
        if await input_element.is_visible() and not await input_element.is_checked():
            await input_element.check()

    async def handle_checkbox_or_radio(self, input_element):
        # 检查元素是否可见且未被选中或禁用
        try:
            await asyncio.wait_for(input_element.check(), timeout=1)
            # 等待短暂时间让页面逻辑执行
            await asyncio.sleep(0.5)
        except Exception as e:
            print(f"Error while handling input: {e}")
            label = await input_element.query_selector('xpath=following-sibling::label')
            if label and await label.is_visible():
                try:
                    await label.click()
                    await asyncio.sleep(0.5)  # 等待页面逻辑执行
                    return
                except Exception as e:
                    print(f"Error while clicking label: {e}")

    async def handle_inputs(self, page):
        inputs = await page.query_selector_all('input')
        for input_element in inputs:
            if await input_element.is_visible() and not (
                    await input_element.get_attribute('type') == 'hidden') and not await input_element.is_disabled():
                input_type = await input_element.get_attribute('type')
                if input_type in ['checkbox', 'radio']:
                    # 处理复选框和单选按钮
                    await self.handle_checkbox_or_radio(input_element)
                    # 重新获取页面上的输入元素，因为状态可能已经改变
                    inputs = await page.query_selector_all('input')
                else:
                    # 处理其他类型的输入元素
                    await self.handle_normal_input(input_element)
        # input_type = await input_element.get_attribute('type')
        # if input_type == 'checkbox':
        #     await self.handle_checkbox(input_element)
        # elif input_type == 'radio':
        #     await self.handle_radio(input_element)
        # else:
        #     await self.handle_normal_input(input_element)

    async def handle_checkbox(self, input_element):
        try:
            # await input_element.check()  # 勾选复选框
            await asyncio.wait_for(input_element.check(), timeout=1)
        except Exception as e:
            print(e)

    async def handle_normal_input(self, input_element):
        # 获取 input 元素的外部 HTML
        input_html = await input_element.evaluate("element => element.outerHTML")

        # 尝试获取关联的 label 文本
        label = await input_element.query_selector('xpath=../label') or await input_element.query_selector(
            'xpath=preceding-sibling::label')
        label_text = ''
        if label:
            label_text = await label.evaluate("element => element.textContent")

        # 获取 placeholder 属性
        placeholder = await input_element.get_attribute('placeholder') or ''

        # 构建更完整的上下文
        context_html = f"Label: {label_text}\nPlaceholder: {placeholder}\nInput HTML: {input_html}"

        print(f"Context HTML: {context_html}")
        # 使用上下文调用 GPT-3.5
        predicted_text = await self.get_prediction_from_gpt(context_html)
        await input_element.fill(predicted_text)

    # async def handle_normal_input(self, input_element):
    #     # 使用 page.evaluate() 来获取元素的 outerHTML
    #     input_html = await input_element.evaluate("element => element.outerHTML")
    #     print(f"Input HTML: {input_html}")
    #     # 继续您的逻辑
    #     predicted_text = await self.get_prediction_from_gpt(input_html)
    #     await input_element.fill(predicted_text)

    async def get_prediction_from_gpt(self, input_html):
        prompt = f"我将提供一段HTML代码，其中包含一个input。请告诉我，最可能会填入该input字段的值, 请必须猜测并给出一个值。如果有报错信息，请随机给出一个符合该input要求的数据，例如'random'或者1500。请注意，我只需要您提供的答案，不需要额外的解释、文字或者报错信息。\n{input_html}"

        # 准备请求体
        payload = {
            "model": "gpt-4",
            "messages": [{"role": "user", "content": prompt, "temperature": 0.8}]
        }

        # payload = json.dumps({
        #     "model": "gpt-3.5-turbo",
        #     "prompt": prompt,
        #     "temperature": 0.7
        # })

        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }

        # 发送请求到ChatGPT 3.5 Turbo API
        async with aiohttp.ClientSession() as session:
            async with session.post('https://api.chatanywhere.com.cn/v1/chat/completions', headers=headers,
                                    json=payload) as response:
                if response.status == 200:
                    response_data = await response.json()
                    # 假设返回的数据中包含答案
                    answer = response_data['choices'][0]['message']['content'] if 'choices' in response_data and \
                                                                                  response_data[
                                                                                      'choices'] else "No answer found."
                    if type(answer) == "str":
                        answer = answer.strip("\"")
                    log.info(f"prediction: {answer}")
                    return answer
                else:
                    print(f"Error: Failed to get response from GPT-3.5 Turbo API, status code: {response.status}")
                    return "Error in API call"

    async def parse_html(self, page):
        """
        解析页面内容
        :param page: Playwright的Page实例
        """
        log.info("Parsing HTML")
        # 等待网络加载完成
        await page.wait_for_load_state('networkidle')
        content = await page.content()

        # 解析页面中的URL并添加到URLManager
        hrefs = await page.query_selector_all('a')
        for href in hrefs:
            url = await href.get_attribute('href')
            if url:
                # 假设页面URL是绝对路径，或者需要与基础URL结合
                full_url = urljoin(page.url, url)
                self.url_manager.add_new_url(full_url)

        # 检查页面是否包含登录相关的元素
        # content = await page.content()
        # login_indicators = ["login", "登录", "submit", "提交"]
        # username_fields = ["username", "name", "user"]
        # password_fields = ["password", "passwd"]
        #
        # # 检测用户名和密码输入框
        # username_selector = None
        # password_selector = None

        username_selector, password_selector = await self.authcheck(page)
        if username_selector and password_selector:
            await self.login(page, username_selector, password_selector)
            storage = await page.context.storage_state(path="state.json")
        else:
            # 查找并处理所有input元素
            # inputs = await page.query_selector_all('input')
            await self.handle_inputs(page)
            # for input_element in inputs:
            #     # 检查元素是否可见且类型不是hidden
            #     if await input_element.is_visible() and not (await input_element.get_attribute('type') == 'hidden') and not await input_element.is_disabled():
            #         await self.handle_input(input_element)
                    # input_type = await input_element.get_attribute('type')
                    # if input_type != 'hidden':
                    #     if input_type == 'checkbox':
                    #         # 如果是复选框，根据需要勾选或取消勾选
                    #         # 这里示例是勾选复选框，如果需要根据实际情况取消勾选，可以使用uncheck()
                    #         await input_element.check()
                    #     elif input_type in ['text', 'password', 'email']:
                    #         # 对于文本、密码或邮箱输入框，填充随机文本
                    #         input_html = await input_element.inner_html()
                    #         print(f"Input HTML: {input_html}")
                    #         await input_element.fill('random')

            # 拦截网络请求，点击所有button但不实际发送请求
            await page.route('**/*', lambda route: asyncio.create_task(self.handle_route(route, page)))

            buttons = await page.query_selector_all('button')
            for button in buttons:
                # 检查按钮是否可见且未被禁用
                if await button.is_visible() and not await button.is_disabled():
                    try:
                        await button.click()
                        print("按钮已点击")
                    except Exception as e:
                        print(f"点击按钮时发生错误: {e}")
                else:
                    print("按钮不可点击")
            # 取消拦截网络请求
            await page.unroute('**/*')

        # 解析页面中的URL并添加到URLManager
        time.sleep(1)
        await page.wait_for_load_state('networkidle')
        content = await page.content()
        hrefs = await page.query_selector_all('a')
        for href in hrefs:
            url = await href.get_attribute('href')
            if url:
                # 假设页面URL是绝对路径，或者需要与基础URL结合
                full_url = urljoin(page.url, url)
                self.url_manager.add_new_url(full_url)


    async def handle_route(self, route, page):
        # 获取请求对象
        request = route.request

        # 从完整URL中提取路径
        parsed_url = urlparse(request.url)
        path = parsed_url.path
        if parsed_url.query:
            path += '?' + parsed_url.query

        # 构建请求数据包内容
        request_headers = request.headers
        # 确保Host头存在
        if 'host' not in request_headers:
            request_headers['Host'] = parsed_url.netloc

        # 构建HTTP请求头部
        request_headers_text = "\n".join([f"{name}: {value}" for name, value in request_headers.items()])

        # 获取POST数据
        post_data = request.post_data if request.post_data else ""

        # 构建HTTP请求体
        request_data = f"{request.method} {path} HTTP/1.1\n{request_headers_text}\n\n{post_data}"

        # 保存请求数据到文件
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        file_path = os.path.join('./crawler', f"{timestamp}.txt")
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w') as f:
            f.write(request_data)

        # 修改请求以避免实际发出
        # await route.continue_(url="http://192.168.0.1" + path, method="GET")
        await route.abort()


