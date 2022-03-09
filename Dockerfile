FROM python:alpine3.14

RUN pip3 install requests

ADD disco.py /

CMD [ "python", "./disco.py" ]
