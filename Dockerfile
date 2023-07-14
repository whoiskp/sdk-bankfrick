FROM python:3.8-slim-bullseye

COPY requirements.txt /
RUN pip --no-cache-dir install -r requirements.txt

COPY . /webapps

WORKDIR /webapps

