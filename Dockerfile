FROM python:alpine3.14
WORKDIR ./disco
RUN pip3 install requests

COPY . ./

CMD ["python", "-u", "./disco.py", "-n", "3", "-i", "120", "-m", "helium-miner:4467"]