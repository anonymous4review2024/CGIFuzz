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
        log.info("Resolver init")
        self.url_manager = url_manager
        self.username = "admin"
        self.password = "admin"
        self.api_key = "sk-3EukPVUuMm6y4hCXBD55Zo3qZ1F2hjxLneJ2TAKk4PGKDFVq"
        self.cookies = []  # 用于存储登录后获取的cookie

    async def find_field(self, page: Page, selectors):
        for selector in selectors:
            field = await page.query_selector(selector)
            if field:
                return selector
        return None


    async def authcheck(self, page: Page):
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
        # await page.context.add_cookies(self.cookies)

    async def handle_radio(self, input_element):
        if await input_element.is_visible() and not await input_element.is_checked():
            await input_element.check()

    async def handle_checkbox_or_radio(self, input_element):
        try:
            await asyncio.wait_for(input_element.check(), timeout=1)
            await asyncio.sleep(0.5)
        except Exception as e:
            print(f"Error while handling input: {e}")
            label = await input_element.query_selector('xpath=following-sibling::label')
            if label and await label.is_visible():
                try:
                    await label.click()
                    await asyncio.sleep(0.5)  
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
                    await self.handle_checkbox_or_radio(input_element)
                    inputs = await page.query_selector_all('input')
                else:
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
            # await input_element.check()  
            await asyncio.wait_for(input_element.check(), timeout=1)
        except Exception as e:
            print(e)

    async def handle_normal_input(self, input_element):
        input_html = await input_element.evaluate("element => element.outerHTML")

        label = await input_element.query_selector('xpath=../label') or await input_element.query_selector(
            'xpath=preceding-sibling::label')
        label_text = ''
        if label:
            label_text = await label.evaluate("element => element.textContent")

        placeholder = await input_element.get_attribute('placeholder') or ''


        context_html = f"Label: {label_text}\nPlaceholder: {placeholder}\nInput HTML: {input_html}"

        print(f"Context HTML: {context_html}")
        predicted_text = await self.get_prediction_from_gpt(context_html)
        await input_element.fill(predicted_text)


    async def get_prediction_from_gpt(self, input_html):
        prompt = f"I will provide a snippet of HTML code containing an input field. Please tell me the most likely value that would be entered into this input field. You must guess and provide a single value. If there is an error in determining the value, please randomly generate an appropriate value that fits the input requirements, such as 'random' or 1500. Note: I only need your answer — no extra explanations, text, or error messages.\n{input_html}"

        payload = {
            "model": "gpt-4",
            "messages": [{"role": "user", "content": prompt, "temperature": 0.8}]
        }


        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }

        async with aiohttp.ClientSession() as session:
            async with session.post('https://api.chatanywhere.com.cn/v1/chat/completions', headers=headers,
                                    json=payload) as response:
                if response.status == 200:
                    response_data = await response.json()
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
        log.info("Parsing HTML")
        await page.wait_for_load_state('networkidle')
        content = await page.content()

        hrefs = await page.query_selector_all('a')
        for href in hrefs:
            url = await href.get_attribute('href')
            if url:
                full_url = urljoin(page.url, url)
                self.url_manager.add_new_url(full_url)


        username_selector, password_selector = await self.authcheck(page)
        if username_selector and password_selector:
            await self.login(page, username_selector, password_selector)
            storage = await page.context.storage_state(path="state.json")
        else:
            await self.handle_inputs(page)
            await page.route('**/*', lambda route: asyncio.create_task(self.handle_route(route, page)))

            buttons = await page.query_selector_all('button')
            for button in buttons:
                if await button.is_visible() and not await button.is_disabled():
                    try:
                        await button.click()
                        print("按钮已点击")
                    except Exception as e:
                        print(f"点击按钮时发生错误: {e}")
                else:
                    print("按钮不可点击")
            await page.unroute('**/*')

        time.sleep(1)
        await page.wait_for_load_state('networkidle')
        content = await page.content()
        hrefs = await page.query_selector_all('a')
        for href in hrefs:
            url = await href.get_attribute('href')
            if url:
                full_url = urljoin(page.url, url)
                self.url_manager.add_new_url(full_url)


    async def handle_route(self, route, page):
        request = route.request

        parsed_url = urlparse(request.url)
        path = parsed_url.path
        if parsed_url.query:
            path += '?' + parsed_url.query

        request_headers = request.headers

        if 'host' not in request_headers:
            request_headers['Host'] = parsed_url.netloc

        request_headers_text = "\n".join([f"{name}: {value}" for name, value in request_headers.items()])


        post_data = request.post_data if request.post_data else ""

        request_data = f"{request.method} {path} HTTP/1.1\n{request_headers_text}\n\n{post_data}"

        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        file_path = os.path.join('./crawler', f"{timestamp}.txt")
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w') as f:
            f.write(request_data)

        await route.abort()


