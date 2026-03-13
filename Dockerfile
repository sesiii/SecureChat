FROM python:3.9-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir bcrypt redis

ENTRYPOINT ["python", "server.py"]