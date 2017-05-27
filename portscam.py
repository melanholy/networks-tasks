import socket
import argparse
from concurrent.futures import ThreadPoolExecutor

'''
еще не доделано
TCP_PROTOCOL_CHECKS = {
    'HTTP': (
        b'GET / HTTP/1.1\r\nHost: google.com\r\n\r\n',
        b'HTTP/1.1'
    ),
    'SMTP': (
        b'EHLO 452423',
        b'stub'
    ),
    'POP3': (
        b'USER python',
        b'PASS'
    )
}
DNS_TRANS_ID = struct.pack('!H', random.randint(0, 65000))
UDP_PROTOCOL_CHECKS = {
    'NTP': (
        struct.pack(
            "!BBBbIIIIIIIIIII",
            (2 << 3) | 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ),
        b'stub'
    ),
    'DNS': (
        DNS_TRANS_ID+b'\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01',
        DNS_TRANS_ID
    )
}

def check_port_udp(port, addr):
    pass

def check_protocols(address, port):
    res = []
    for proto, signs in TCP_PROTOCOL_CHECKS.items():
        with socket.socket() as sock:
            sock.settimeout(3)
            try:
                sock.connect((address, port))
            except socket.timeout:
                return []
'''

def check_port_tcp(port, addr):
    '''
    Пытается подсоединиться к указанному хосту по указанному
    порту и сообщает результат.
    Законнектились - значит порт открыт, иначе считаем его закрытым.
    '''
    sock = socket.socket()
    sock.settimeout(3)
    try:
        with sock:
            sock.connect((addr, port))
    except socket.timeout:
        return False, port

    return True, port

def scan_ports(addr, start, end):
    '''
    Многопоточно сканирует хост на предмет открытых TCP портов.
    '''
    addr = socket.gethostbyname(addr)
    executor = ThreadPoolExecutor(max_workers=65536)
    with executor:
        results = executor.map(check_port_tcp, range(start, end + 1), [addr] * (end + 1 - start))
        for res, port in results:
            if res:
                yield port

def main():
    parser = argparse.ArgumentParser(
        description='Portscan. TCP only.',
        epilog='Usage example: portscam.py google.com 21 80'
    )
    parser.add_argument(
        'address', type=str,
        help='address to scan')
    parser.add_argument(
        'start', type=int,
        help='starting port'
    )
    parser.add_argument(
        'end', type=int,
        help='end port'#. Ignored if --proto is present(only start port will be checked).'
    )
    #parser.add_argument('--proto', action='store_const', const=True)
    args = parser.parse_args()
    # if args.proto:
    #     protocols = check_protocols(args.address, address.start)
    # else:
    for port in scan_ports(args.address, args.start, args.end):
        print(port, 'is opened')

if __name__ == '__main__':
    main()
