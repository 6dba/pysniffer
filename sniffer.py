from typing import Any, Optional
from scapy.all import *
from scapy.layers.http import HTTPRequest
from colorama import init, Fore
from datetime import datetime

# COLORAMA
init()

GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET
WHITE = Fore.WHITE


def sniff_packets(interface: Optional[str] = None) -> None:
    """
    Перехват пакетов 80 портов с помощью 'iface', если None (по умолчанию), то
    используется интерфейс scapy

    :param Optional[str] iface: Опциональный сетевой интерфейс
    :rtype: None
    """
    if interface:
        print(
            f"\n{WHITE}[!] Start sniffing HTTP with interface {interface} {RESET}")
        # 'process_packet' - коллбек функция, которая вызывается для каждого пакета
        sniff(filter="port 80", prn=process_packet,
              iface=interface, store=False)
    else:
        print(f"\n{WHITE}[!] Start sniffing HTTP {RESET}")
        sniff(filter="port 80", prn=process_packet, store=False)


def process_packet(packet: Any) -> None:
    """
    Эта функция выполняется всякий раз, когда пакет прослушивается.

    :param Any packet: Перехваченный пакет данных HTTP
    :rtype: None
    """
    if packet.haslayer(HTTPRequest):
        # Получение полей пакета
        url = packet[HTTPRequest].Host.decode(
        ) + packet[HTTPRequest].Path.decode()
        src = packet[IP].src
        dst = packet[IP].dst
        method = packet[HTTPRequest].Method.decode()

        # packet.show() # for more information about packet

        print(
            f"\n{GREEN}[+] {WHITE}[{datetime.now()}]{GREEN} src: {WHITE}{src}{GREEN} Requested {url} dst: {WHITE}{dst}{GREEN} with {method}{RESET}")

        if is_raw and packet.haslayer(Raw) and method == "POST":
            # если флаг is_raw включен и пакет содержит отправляемые POST данные
            print(
                f"\n{RED}[*] {WHITE}[{datetime.now()}]{RED} Some useful raw data: {packet[Raw].load}{RESET}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Сниффер HTTP-пакетов")
    parser.add_argument(
        "-i", "--interface", help="Сетевой интерфейс для использования, по умолчанию используется интерфейс scapy. " +
        "Для Windows, имя интерфейсов указывать исключительно на EN!")
    parser.add_argument("--show-raw", dest="raw", action="store_true",
                        help="Печатать ли необработанные данные POST запроса, такие как пароли, поисковые запросы и т. д.")

    args = parser.parse_args()

    interface = args.interface
    is_raw = args.raw

    sniff_packets(interface=interface)