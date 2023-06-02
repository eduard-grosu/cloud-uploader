FROM python:3.8-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_RUN_PORT=5001
ENV FLASK_APP=project

EXPOSE 5001

CMD ["flask", "run", "--port=5001"]
