FROM python:3.9

ENV CONTAINER_HOME=/var/www
ADD . $CONTAINER_HOME
WORKDIR $CONTAINER_HOME
RUN python3 -m pip install -r $CONTAINER_HOME/requirements.txt