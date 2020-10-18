# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     zhihu_login.py 
   Description :   Forked from https://github.com/zkqiang/zhihu-login，并增加了推荐内容的爬取
   Author :        LSQ
   date：          2020/10/16
-------------------------------------------------
   Change Activity:
                   2020/10/16: None
-------------------------------------------------
"""

import base64
import hashlib
import hmac
import json
import re
import threading
import time
import random
# 日志模块
import logging
import sys

import pytesseract
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from http import cookiejar
from urllib.parse import urlencode
import execjs
import requests
from PIL import Image


class ZhihuAccount(object):
    """
    使用时请确定安装了 Node.js（7.0 以上版本） 或其他 JS 环境
    报错 execjs._exceptions.ProgramError: TypeError: 'exports' 就是没有安装
    然后在当前目录下执行: `$npm install jsdom`
    """

    def __init__(self, username: str = None, password: str = None, logger=None):
        self.logger = logger
        self.username = username
        self.password = password

        self.login_data = {
            'client_id': 'c3cef7c66a1843f8b3a9e6a1e3160e20',
            'grant_type': 'password',
            'source': 'com.zhihu.web',
            'username': '',
            'password': '',
            'lang': 'en',
            'ref_source': 'other_https://www.zhihu.com/signin?next=%2F',
            'utm_source': ''
        }
        self.session = requests.session()
        self.session.headers = {
            'accept-encoding': 'gzip, deflate, br',
            'Host': 'www.zhihu.com',
            'Referer': 'https://www.zhihu.com/',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                          '(KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36'
        }
        self.session.cookies = cookiejar.LWPCookieJar(filename='./cookies.txt')

    def login(self, captcha_lang: str = 'en', load_cookies: bool = True):
        """
        模拟登录知乎
        :param captcha_lang: 验证码类型 'en' or 'cn'
        :param load_cookies: 是否读取上次保存的 Cookies
        :return: bool
        若在 PyCharm 下使用中文验证出现无法点击的问题，
        需要在 Settings / Tools / Python Scientific / Show Plots in Toolwindow，取消勾选
        """
        if load_cookies and self.load_cookies():
            self.logger.info('读取 Cookies 文件')
            if self.check_login():
                self.logger.info('登录成功')
                return True
            self.logger.warning('Cookies 已过期')

        self._check_user_pass()
        self.login_data.update({
            'username': self.username,
            'password': self.password,
            'lang': captcha_lang
        })

        timestamp = int(time.time() * 1000)
        self.login_data.update({
            'captcha': self._get_captcha(self.login_data['lang']),
            'timestamp': timestamp,
            'signature': self._get_signature(timestamp)
        })

        headers = self.session.headers.copy()
        headers.update({
            'content-type': 'application/x-www-form-urlencoded',
            'x-zse-83': '3_2.0',
            'x-xsrftoken': self._get_xsrf()
        })
        data = self._encrypt(self.login_data)
        login_api = 'https://www.zhihu.com/api/v3/oauth/sign_in'
        resp = self.session.post(login_api, data=data, headers=headers)
        if 'error' in resp.text:
            self.logger.warning(json.loads(resp.text)['error'])
        if self.check_login():
            self.logger.info('登录成功')
            return True
        self.logger.warning('登录失败')
        return False

    def load_cookies(self):
        """
        读取 Cookies 文件加载到 Session
        :return: bool
        """
        try:
            self.session.cookies.load(ignore_discard=True)
            return True
        except FileNotFoundError:
            return False

    def check_login(self):
        """
        检查登录状态，访问登录页面出现跳转则是已登录，
        如登录成功保存当前 Cookies
        :return: bool
        """
        login_url = 'https://www.zhihu.com/signup'
        resp = self.session.get(login_url, allow_redirects=False)
        if resp.status_code == 302:
            self.session.cookies.save()
            return True
        return False

    def _get_xsrf(self):
        """
        从登录页面获取 xsrf
        :return: str
        """
        self.session.get('https://www.zhihu.com/', allow_redirects=False)
        for c in self.session.cookies:
            if c.name == '_xsrf':
                return c.value
        raise AssertionError('获取 xsrf 失败')

    def _get_captcha(self, lang: str):
        """
        请求验证码的 API 接口，无论是否需要验证码都需要请求一次
        如果需要验证码会返回图片的 base64 编码
        根据 lang 参数匹配验证码，需要人工输入
        :param lang: 返回验证码的语言(en/cn)
        :return: 验证码的 POST 参数
        """
        if lang == 'cn':
            api = 'https://www.zhihu.com/api/v3/oauth/captcha?lang=cn'
        else:
            api = 'https://www.zhihu.com/api/v3/oauth/captcha?lang=en'
        resp = self.session.get(api)
        show_captcha = re.search(r'true', resp.text)

        if show_captcha:
            put_resp = self.session.put(api)
            json_data = json.loads(put_resp.text)
            img_base64 = json_data['img_base64'].replace(r'\n', '')
            with open('./captcha.jpg', 'wb') as f:
                f.write(base64.b64decode(img_base64))
            img = Image.open('./captcha.jpg')
            if lang == 'cn':
                import matplotlib.pyplot as plt
                plt.imshow(img)
                self.logger.info('点击所有倒立的汉字，在命令行中按回车提交')
                points = plt.ginput(7)
                capt = json.dumps({'img_size': [200, 44],
                                   'input_points': [[i[0] / 2, i[1] / 2] for i in points]})
            else:
                img_thread = threading.Thread(target=img.show, daemon=True)
                img_thread.start()
                # 这里可自行集成验证码识别模块
                capt = input('请输入图片里的验证码：')
            # 这里必须先把参数 POST 验证码接口
            self.session.post(api, data={'input_text': capt})
            return capt
        return ''

    def _generate_captcha_text(self, img_stream):
        return pytesseract.image_to_string(img_stream)

    def _get_signature(self, timestamp: int or str):
        """
        通过 Hmac 算法计算返回签名
        实际是几个固定字符串加时间戳
        :param timestamp: 时间戳
        :return: 签名
        """
        ha = hmac.new(b'd1b964811afb40118a12068ff74a12f4', digestmod=hashlib.sha1)
        grant_type = self.login_data['grant_type']
        client_id = self.login_data['client_id']
        source = self.login_data['source']
        # ha.update(bytes((grant_type + client_id + source + str(timestamp)), 'utf-8'))
        ha.update((grant_type + client_id + source + str(timestamp)).encode('utf-8'))
        return ha.hexdigest()

    def _check_user_pass(self):
        """
        检查用户名和密码是否已输入，若无则手动输入
        """
        if not self.username:
            self.username = input('请输入手机号：')
        if self.username.isdigit() and '+86' not in self.username:
            self.username = '+86' + self.username

        if not self.password:
            self.password = input('请输入密码：')

    @staticmethod
    def _encrypt(form_data: dict):
        with open('./encrypt.js') as f:
            js = execjs.compile(f.read())
            # js = execjs.compile(f.read(), cwd=r'C:\Users\Administrator\AppData\Roaming\npm\node_modules')
            return js.call('b', urlencode(form_data))


class ZhihuCrawler(object):
    '''
    本项目爬取的是用户登录后的推荐内容。
    数据类型主要分为三种：zvideo、answer、article，zvideo和article好像都没啥用。这里只抓取了answer和article两种类型。
    '''

    def __init__(self, username=None, password=None):
        # 初始化日志功能
        self.logger = Logger().logger
        # 初始化cookie
        self.account = ZhihuAccount(username, password, logger=self.logger)
        self.account.login(captcha_lang='en', load_cookies=True)
        # session加载cookie
        self.session = requests.session()
        self.session.cookies = cookiejar.LWPCookieJar(filename='./cookies.txt')
        self.session.cookies.load(ignore_discard=True)
        self.first_url = 'https://www.zhihu.com/'
        self.headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36',
        }
        # 初始化mongodb数据库
        self.mongo = MongoClient('mongodb://127.0.0.1:27017')
        self.collection = self.mongo['zhihu']['data']

    def __del__(self):
        self.mongo.close()

    def _get_page(self, next_url=None):
        url = next_url
        try:
            if url is None:
                self.logger.info('正在获取第一页***')
                resp = self.session.get(self.first_url, headers=self.headers)
                if resp.status_code == 200:
                    return resp
                else:
                    raise Exception(f'{resp.status_code}')
            else:
                url = url.encode().decode("raw_unicode_escape")
                headers = self.headers
                headers['referer'] = 'https://www.zhihu.com/'
                self.logger.info(f'正在获取下一页***{url}')
                resp = self.session.get(url, headers=headers)
                if resp.status_code == 200:
                    return resp
                else:
                    raise Exception(f'{resp.status_code}')

        except:
            self.account.login(captcha_lang='en', load_cookies=False)
            self.session.cookies = cookiejar.LWPCookieJar(filename='./cookies.txt')
            self.session.cookies.load(ignore_discard=True)
            self.logger.warning(f'Encountered a cookie error, now retrying _get_page({url}).')
            time.sleep(random.uniform(1, 4))
            self._get_page(url)

    def _get_first_page_html(self, response):
        html = response.content.decode()
        # with open('zhihu.html', 'w', encoding='utf-8') as f:
        #     f.write(html)
        return html

    def _get_first_page_data(self, html):
        data = dict()
        initial_data = re.findall('<script id="js-initialData" type="text/json">(.*?)</script>', html).pop()
        initial_data = initial_data.encode().decode('raw_unicode_escape')
        json_data = json.loads(initial_data)
        json_answers = json_data['initialState']['entities'].get('answers')
        item_list = list()
        for answer_id, detail in json_answers.items():
            # item文章
            item = dict()
            item['id'] = answer_id
            item['type'] = detail.get('type', None)
            item['url'] = detail.get('url', None)
            item['author'] = dict()
            item['author']['userType'] = detail['author'].get('userType', None)
            item['author']['name'] = detail['author'].get('name', None)
            item['createdTime'] = detail.get('createdTime', None)
            item['updatedTime'] = detail.get('updatedTime', None)
            item['votedupCount'] = detail.get('voteupCount', None)
            item['thanksCount'] = detail.get('thanksCount', None)
            item['commentCount'] = detail.get('commentCount', None)
            item['question'] = dict()
            item['question']['id'] = detail['question'].get('id', None)
            item['question']['type'] = detail['question'].get('type', None)
            item['question']['url'] = detail['question'].get('url', None)
            item['question']['title'] = detail['question'].get('title', None)
            item['content'] = detail.get('content', None)
            item_list.append(item)
        is_end = re.findall('"is_end":false', html).pop()
        if 'false' in is_end:
            next_url = re.findall('"paging".*?"next":"(.*?)"', html, re.DOTALL).pop()
            data['next_url'] = next_url
        data['item_list'] = item_list
        return data

    def _save_data(self, data):
        for item in data.get('item_list'):
            item['_id'] = item.get('id')
            try:
                self.collection.insert_one(item)
            except DuplicateKeyError as e:
                self.logger.warning(e)
        return

    def _get_json(self, response):
        return response.json()

    def _get_data(self, json):
        data = dict()
        item_list = list()
        for each in json.get('data'):
            print(each['target'].get('type'))
            if each['target'].get('type') == 'zvideo':
                continue
            item = dict()
            target = each.get('target')
            item['id'] = target.get('id', None)
            item['type'] = target.get('type', None)
            item['url'] = target.get('url', None)
            item['author'] = dict()
            item['author']['userType'] = target['author'].get('user_type', None)
            item['author']['name'] = target['author'].get('name', None)
            item['createdTime'] = target.get('created_time', None)
            item['updatedTime'] = target.get('updated_time', None)
            item['votedupCount'] = target.get('voteup_count', None)
            item['thanksCount'] = target.get('thanks_count', None)
            item['commentCount'] = target.get('comment_count', None)
            if item['type'] == 'answer':
                item['question'] = dict()
                item['question']['id'] = target['question'].get('id', None)
                item['question']['type'] = target['question'].get('type', None)
                item['question']['url'] = target['question'].get('url', None)
                item['question']['title'] = target['question'].get('title', None)
            item['content'] = target.get('content', None)
            item_list.append(item)
        is_end = json['paging'].get('is_end')
        if not is_end:
            next_url = json['paging'].get('next')
            data['next_url'] = next_url.encode().decode('raw_unicode_escape')
        data['item_list'] = item_list
        return data

    def run(self):
        self.logger.info('开始爬取***')
        next_url = None
        # 1 发起首页请求、获取响应
        response = self._get_page(next_url)
        # 2 解析响应
        html = self._get_first_page_html(response)
        # 3 提取数据
        data = self._get_first_page_data(html)
        # 4 保存数据
        self._save_data(data)
        # 下一页请求
        next_url = data.get('next_url', None)
        time.sleep(5)
        while True:
            # try:
            # 1 发起请求、获取响应
            response = self._get_page(next_url)
            # 2 解析响应
            json = self._get_json(response)
            # 3 提取数据
            data = self._get_data(json)
            # 4 保存数据
            self._save_data(data)
            # 下一页请求
            next_url = data.get('next_url', None)
            if next_url is None:
                break
            time.sleep(5)
            # except Exception as e:
            #     print(e)
        self.logger.info('爬取结束***')


class Logger(object):
    def __init__(self):
        # 获取logger对象
        self._logger = logging.getLogger()
        # 设置formart对象
        self.formatter = logging.Formatter(fmt='%(asctime)s %(filename)s [line:%(lineno)d] %(levelname)s: %(message)s',
                                           datefmt='%Y-%m-%d %H:%M:%S')
        # 设置日志输出
        self._logger.addHandler(self._get_file_handler('log.log'))
        self._logger.addHandler(self._get_console_handler())
        # 设置日志等级
        self._logger.setLevel(logging.INFO)

    def _get_file_handler(self, filename):
        '''
        获取文件日志handler
        :param filename: 文件名
        :return: filehandler
        '''
        # 实例化filehandler类
        filehandler = logging.FileHandler(filename=filename, encoding='utf-8')
        # 设置日志格式
        filehandler.setFormatter(self.formatter)
        return filehandler

    def _get_console_handler(self):
        '''
        获取终端日志handler
        :return: consolehandler
        '''
        # 实例化streamhandler类
        consolehandler = logging.StreamHandler(sys.stdout)
        # 设置日志格式
        consolehandler.setFormatter(self.formatter)
        return consolehandler

    @property
    def logger(self):
        return self._logger


if __name__ == '__main__':
    # 输入用户名和密码进行登录
    username = ''
    password = ''
    crawler = ZhihuCrawler(username, password)
    crawler.run()
