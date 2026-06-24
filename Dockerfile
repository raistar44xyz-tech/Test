FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt pymongo

COPY bot.py checker.py dashboard.py mongodb_store.py password_changer.py proxy_manager.py stats.py ./

ENV TELEGRAM_BOT_TOKEN=""
ENV MONGODB_URL=""
ENV ADMIN_ID=""

EXPOSE 5000

CMD ["python", "bot.py"]
