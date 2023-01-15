FROM python:3.9
COPY setup.py /home/
COPY app/* /home/
WORKDIR /home
RUN pip3 install -e .
COPY requirements.txt .
RUN python3 -m pip install -r requirements.txt
ENTRYPOINT FLASK_APP=app.py flask run --host=0.0.0.0