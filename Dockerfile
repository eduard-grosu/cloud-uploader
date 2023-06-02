FROM python:3.8-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_RUN_PORT=5001
ENV FLASK_APP=project

EXPOSE 5001

CMD ["flask", "run", "--host=0.0.0.0", "--port=5001"]
