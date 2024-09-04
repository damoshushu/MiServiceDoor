import base64
import hashlib
import json
import logging
import os
import random
import string
from urllib import parse
from aiohttp import ClientSession
from aiofiles import open as async_open

_LOGGER = logging.getLogger(__package__)


def get_random(length):
    return ''.join(random.sample(string.ascii_letters + string.digits, length))


class MiTokenStore:

    def __init__(self, token_path):
        self.token_path = token_path

    async def load_token(self):
        if os.path.isfile(self.token_path):
            try:
                async with async_open(self.token_path) as f:                    
                    return json.loads(await f.read())
            except Exception as e:
                _LOGGER.exception("Exception on load token from %s: %s", self.token_path, e)
        return None

    async def save_token(self, token=None):
        if token:
            try:
                async with async_open(self.token_path, 'w') as f:
                    await f.write(json.dumps(token, indent=2))
            except Exception as e:
                _LOGGER.exception("Exception on save token to %s: %s", self.token_path, e)
        elif os.path.isfile(self.token_path):
            os.remove(self.token_path)


class MiAccount:

    def __init__(self, session: ClientSession, username, password, token_store='.mi.token'):
        self.session = session
        self.username = username
        self.password = password
        self.token_store = MiTokenStore(token_store) if isinstance(token_store, str) else token_store
        self.token = None

    async def login(self, sid):
        if not self.token:
            #self.token = {'deviceId': get_random(16).upper()}
            self.token = {'deviceId': "099780910E3C802D"}
        try:
            resp = await self._serviceLogin(f'serviceLogin?sid={sid}&_json=true')
            if resp['code'] != 0:
                data = {
                    '_json': 'true',
                    'qs': resp['qs'],
                    'sid': resp['sid'],
                    '_sign': resp['_sign'],
                    'callback': resp['callback'],
                    'user': self.username,
                    'cc': '+86',
                    'hash': hashlib.md5(self.password.encode()).hexdigest().upper()
                }
                resp = await self._serviceLogin('serviceLoginAuth2', data)
                if resp['code'] != 0:
                    raise Exception(resp)

            self.token['userId'] = resp['userId']
            self.token['passToken'] = resp['passToken']

            serviceToken = await self._securityTokenService(resp['location'], resp['nonce'], resp['ssecurity'])
            self.token[sid] = (resp['ssecurity'], serviceToken)
            if self.token_store:
                await self.token_store.save_token(self.token)
            return True

        except Exception as e:
            self.token = None
            if self.token_store:
                await self.token_store.save_token()
            _LOGGER.exception("Exception on login %s: %s", self.username, e)
            return False

    async def _serviceLogin(self, uri, data=None):
        headers = {
            'User-Agent': 'APP/com.xiaomi.mihome APPV/9.1.200 iosPassportSDK/4.2.18 iOS/14.4 miHSTS',
            'Host': 'account.xiaomi.com',
            'Accept': '*/*'
                   }
        cookies = {'sdkVersion': '4.2.18', 'deviceId': self.token['deviceId']}
        if 'passToken' in self.token:
            cookies['userId'] = self.token['userId']
            cookies['passToken'] = self.token['passToken']
        url = 'https://account.xiaomi.com/pass/' + uri
        async with self.session.request('GET' if data is None else 'POST', url, data=data, cookies=cookies, headers=headers) as r:
            raw = await r.read()
            print(raw)
        resp = json.loads(raw[11:])
        _LOGGER.debug("%s: %s", uri, resp)
        return resp

    async def _securityTokenService(self, location, nonce, ssecurity):
        nsec = 'nonce=' + str(nonce) + '&' + ssecurity
        clientSign = base64.b64encode(hashlib.sha1(nsec.encode()).digest()).decode()
        async with self.session.get(location + '&clientSign=' + parse.quote(clientSign)) as r:
            serviceToken = r.cookies['serviceToken'].value
            if not serviceToken:
                raise Exception(await r.text())
        return serviceToken

    async def mi_request(self, sid, url, data, headers, relogin=True, params=None, cookies_add=None):
        if self.token is None and self.token_store is not None:
            self.token = await self.token_store.load_token()
        if (self.token and sid in self.token) or await self.login(sid):  # Ensure login
            cookies = {'userId': self.token['userId'], 'serviceToken': self.token[sid][1]}
            if cookies_add is not None:
                cookies.update(cookies_add)
            content = data(self.token, cookies) if callable(data) else data
            method = 'GET' if (data is None or params is not None) else 'POST'
            _LOGGER.debug("%s %s", url, content)
            async with self.session.request(method, url, data=content, cookies=cookies, headers=headers, params=params) as r:
                status = r.status
                if status == 200:
                    resp = await r.json(content_type=None)
                    code = resp['code']
                    if code == 0:
                        return resp
                    if 'auth' in resp.get('message', '').lower():
                        status = 401
                else:
                    resp = await r.text()
            if status == 401 and relogin:
                _LOGGER.warn("Auth error on request %s %s, relogin...", url, resp)
                self.token = None  # Auth error, reset login
                return await self.mi_request(sid, url, data, headers, False)
        else:
            resp = "Login failed"
        raise Exception(f"Error {url}: {resp}")
