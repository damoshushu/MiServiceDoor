FROM  3.12.5-slim-bookworm

# 设置工作目录
WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

# 运行 Python 程序
CMD ["python", "micli.py", "door"]