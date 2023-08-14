FROM python:3.8-slim-buster

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
WORKDIR /app
EXPOSE 8080

COPY requirements.txt requirements.txt
RUN pip3 install gunicorn
RUN pip3 install -r requirements.txt

COPY . .

CMD gunicorn --bind 0.0.0.0:8080 app:app
