FROM python:3.7-alpine
RUN mkdir /app
WORKDIR /app 
COPY . /app

RUN pip install requests
RUN pip install beautifulsoup4
RUN chmod +x /app/dehashed_api.py
ENTRYPOINT ["./dehashed_api.py"]
