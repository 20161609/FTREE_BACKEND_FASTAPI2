# Python 3.12.2로 변경
FROM python:3.12.2-slim

WORKDIR /app

# requirements.txt 파일을 컨테이너의 /app 디렉토리로 복사
COPY requirements.txt /app

# 필요한 패키지를 설치
RUN pip install --no-cache-dir -r requirements.txt

# 현재 디렉토리의 나머지 파일들을 컨테이너의 /app 디렉토리로 복사
COPY . /app

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
