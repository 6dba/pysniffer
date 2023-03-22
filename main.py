import csv
from typing import Any, Optional
from scapy.all import *
from scapy.layers.http import HTTPRequest
from datetime import datetime
from scapy.layers.inet import IP
from colorama import init, Fore
import PySimpleGUI as sg
import threading
############
global is_raw

GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET
WHITE = Fore.WHITE

def start_sniffing(interface):
    t = threading.Thread(target=sniff_packets, args=(interface,))
    t.start()
def sniff_packets(interface: Optional[str] = None) -> None:
    """
    Перехват пакетов 80 портов с помощью 'iface', если None (по умолчанию), то
    используется интерфейс scapy.

    :param Optional[str] iface: Опциональный сетевой интерфейс
    :rtype: None
    """
    filter = values['port_filter']
    if filter is None or filter == "":
        filter = "80"

    window['output'].print(
        f"\n[!] Start sniffing HTTP with interface {interface if interface else 'scapy'} (port {filter})", text_color='red')
    window.refresh()

    sniff(filter="port "+filter, prn=process_packet, iface=interface, store=False)


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

        # Открыть CSV-файл для записи
        with open('http_traffic.csv', mode='a', newline='') as csv_file:
            fieldnames = ['timestamp', 'source', 'destination', 'method', 'url']
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            # Записать данные в CSV-файл
            writer.writerow({
                'timestamp': datetime.now(),
                'source': src,
                'destination': dst,
                'method': method,
                'url': url
            })

        window['output'].print(f"\n[+] [{datetime.now()}] ", text_color='red')
        window['output'].print(f"src: {src} Requested {url} dst: {dst}", text_color='blue')
        window['output'].print(f"with {method}", text_color='green')
        window.refresh()

        if is_raw and packet.haslayer(Raw) and method == "POST":
            window['output'].print(
                f"\n[*] [{datetime.now()}] Some useful raw data: {packet[Raw].load}")
            window.refresh()


if __name__ == "__main__":

    layout = [[sg.Text('Enter interface (optional):'), sg.InputText(key='interface')],
              [sg.Text('Enter port (optional):'), sg.InputText(key='port_filter',size=(8, 80))],
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
            interface = values['interface']
            #sniff_packets(interface)
            start_sniffing(interface)

    window.close()