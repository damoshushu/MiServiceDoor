import os
from os import environ

from volcenginesdkarkruntime import Ark
from dotenv import load_dotenv


class ARK:
    def __init__(self):
        load_dotenv('env/.env', override=True)
        self.client = Ark(api_key=os.environ.get("ARK_API_KEY"))
        self.endpoints = os.environ.get("ARK_ENDPOINT_IDS").split(',')
        self.endpoint_index = -1

    def get_endpoint(self):
        self.endpoint_index += 1
        if self.endpoint_index >= len(self.endpoints):
            self.endpoint_index = 0
        return self.endpoints[self.endpoint_index]

    async def chat(self, query):
        try:
            endpoint = self.get_endpoint()
            endpoint_name, endpoint_id = endpoint.split(':')
            print("=== 豆包请求:", "模型:", endpoint_name, " 内容:", query, " ===")
            completion = self.client.chat.completions.create(
                model=endpoint_id,
                messages=[
                    {"role": "system", "content": "你是豆包，是由字节跳动开发的 AI 人工智能助手"},
                    {"role": "user", "content": query},
                ],
            )
            print("=== 豆包回复:", completion.choices[0].message.content)
            return completion.choices[0].message.content
        except Exception as e:
            print("### 豆包请求错误", e)


if __name__ == '__main__':
    ark = ARK()
    ark.chat("一棵树有6米高，猴子爬4米就会掉下来2米，请问猴子需要几次才能爬到树顶？")
