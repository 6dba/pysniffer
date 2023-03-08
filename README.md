# HTTP traffic sniffer

![Python Version](https://img.shields.io/badge/python-3.8+-blue?style=for-the-badge&logo=python)

A HTTP Packet Sniffer developed in Python 3.

Monitoring the network always seems to be a useful task for network security engineers, as it enables them to see what is happening in the network, see and control malicious traffic, etc. Once an HTTP request is captured, we extract some information from the packet and print them out.

***Sniffer for traffic analysis is implemented for the discipline "Methodology of safe software development and operation" [IS NSTU](https://ciu.nstu.ru/kaf/zi)***

## Running the Application
Simply clone this repository with `git clone`, install the dependencies and execute the 
`sniffer.py` file.

**You must first install [Npcap](https://npcap.com/)**
```
user@host:~$ git clone https://github.com/6dba/pysniffer.git
user@host:~$ cd pysniffer
user@host:~/packet-sniffer$ pip install -r requirements.txt
user@host:~/packet-sniffer$ sudo python3 sniffer.py
```

*Administrative privileges are required for `scapy` to work correctly and listen to traffic*


## Usage
```
sniffer.py [-h] [-i INTERFACE] [--show-raw]

Сниффер HTTP-пакетов

options:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Сетевой интерфейс для использования, по умолчанию используется интерфейс scapy. Для Windows, имя интерфейсов указывать исключительно на EN!
  --show-raw            Печатать ли необработанные данные POST запроса, такие как пароли, поисковые запросы и т. д.
```