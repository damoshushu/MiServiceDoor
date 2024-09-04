import json
import os

from aiohttp import ClientSession

class Door:
    def __init__(self, token):
        self.session = None
        self.token = token
        if self.session is None:
            self.session = ClientSession()


    async def open_door(self):
        uri = 'https://s.weekey.cn/SmallAPP/Unlock/unlock_new?floor=0'
        headers = {
            'Host': 's.weekey.cn',
            'Accept': 'application/json, text/plain, */*',
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://s.weekey.cn',
            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.50(0x1800323b) NetType/WIFI Language/zh_CN'
        }
        cookies = {
            'PHPSESSID': os.getenv('DOOR_PHPSESSID')
        }
        data = 'gate_id='+os.getenv('DOOR_GATE_ID')
        async with self.session.post(uri, headers=headers, cookies=cookies, data=data) as resp:
            if resp.status == 200:
                result = await resp.text()
                result_obj = json.loads(result)
                door_name = result_obj['data']['gate']['device_desc']
                print("=== 成功打开单元门:", door_name, " ===")
                return "成功打开单元门: " + door_name
            else:
                return "打开单元门失败"