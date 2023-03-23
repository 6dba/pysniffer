# HTTP traffic sniffer

![Python Version](https://img.shields.io/badge/python-3.8+-blue?style=for-the-badge&logo=python)
[![CodeFactor Grade](https://img.shields.io/codefactor/grade/github/6dba/pysniffer?label=CodeFactor&logo=codefactor&style=for-the-badge)](https://www.codefactor.io/repository/github/6dba/pysniffer)

A HTTP Packet Sniffer developed in Python 3.

Monitoring the network always seems to be a useful task for network security engineers, as it enables them to see what is happening in the network, see and control malicious traffic, etc. Once an HTTP request is captured, we extract some information from the packet and print them out.

***Sniffer for traffic analysis is implemented for the discipline "Methodology of safe software development and operation" [IS NSTU](https://ciu.nstu.ru/kaf/zi)***

## Running the Application
Simply clone this repository with `git clone`, install the dependencies and execute the 
`main.py` file.

**You must first install [Npcap](https://npcap.com/)**
```
user@host:~$ git clone https://github.com/6dba/pysniffer.git
user@host:~$ cd pysniffer
user@host:~/pysniffer$ pip install -r requirements.txt
user@host:~/pysniffer$ sudo python3 main.py
```

*Administrative privileges are required for `scapy` to work correctly and listen to traffic*

## Usage
```
user@host:~/pysniffer$ sudo python3 main.py
```