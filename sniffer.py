from typing import Any, Optional
from scapy.all import *
from scapy.layers.http import HTTPRequest
from colorama import init, Fore
from datetime import datetime
from scapy.layers.inet import IP

import PySimpleGUI as sg

init()
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET
WHITE = Fore.WHITE
BLACK = Fore.BLACK

global is_raw


def sniff_packets(interface: Optional[str] = None) -> None:
    """
    Перехват пакетов 80 портов с помощью 'iface', если None (по умолчанию), то
    используется интерфейс scapy.

    :param Optional[str] iface: Опциональный сетевой интерфейс
    :rtype: None
    """
    window['output'].print(
        f"\n[!] Start sniffing HTTP with interface {interface if interface else 'scapy'}")
    window.refresh()

    sniff(filter="port 80", prn=process_packet, iface=interface, store=False)


def process_packet(packet: Any) -> None:
    """
    Эта функция выполняется всякий раз, когда пакет прослушивается.

    :param Any packet: Перехваченный пакет данных HTTP
    :rtype: None
    """
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode(
        ) + packet[HTTPRequest].Path.decode()
        src = packet[IP].src
        dst = packet[IP].dst
        method = packet[HTTPRequest].Method.decode()

        window['output'].print(
            f"\n[+] [{datetime.now()}] src: {src} Requested {url} dst: {dst} with {method}")
        window.refresh()

        if is_raw and packet.haslayer(Raw) and method == "POST":
            window['output'].print(
                f"\n[*] [{datetime.now()}] Some useful raw data: {packet[Raw].load}")
            window.refresh()


if __name__ == "__main__":

    layout = [[sg.Text('Enter interface (optional):'), sg.InputText(key='interface')],
              [sg.Checkbox('Show raw data', key='raw')],
              [sg.Button('Start'), sg.Button('Exit')],
              [sg.Multiline(key='output', size=(80, 20), autoscroll=True)]]

    window = sg.Window('PySniffer', layout)

    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event == 'Exit':
            break
        elif event == 'Start':
            is_raw = values['raw']
            sniff_packets(interface=values['interface'])

    window.close()
