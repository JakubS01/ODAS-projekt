FROM python:3.9
WORKDIR /app
COPY . .
RUN python3 -m pip install -r requirements.txt
CMD gunicorn --bind 0.0.0.0:5000  app:app