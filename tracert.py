import struct
import socket
import argparse
import re

IP_RE = re.compile(r'\d{1,3}')
REFERRAL_RE = re.compile(r'refer:[^\w]+(.+)')
AS_RE = re.compile(r'origin:[^\w]+(\w+)')
COUNTRY_RE = re.compile(r'country:[^\w]+(\w+)')
NETNAME_RE = re.compile(r'netname:[^\w]+(\w+)')
DEFAULT_WHOIS_SERVER = 'whois.ripe.net'
WHOIS_PORT = 43
IPV4_PACKET_LEN = 20
PRIVATE_IP_RANGES = (
    ((10, 0, 0, 0), (10, 255, 255, 255)),
    ((172, 16, 0, 0), (172, 31, 255, 255)),
    ((192, 168, 0, 0), (192, 168, 255, 255))
)

class TraceInfo(object):
    def __init__(self, ttl, addr, is_target=False):
        self.addr = addr
        self.ttl = ttl
        self.is_target = is_target

class ICMP(object):
    @staticmethod
    def construct():
        '''
        Конструирует ICMP Echo Request пакет.
        '''
        #type 8 code 0 - echo request
        type_ = b'\x08\x00'
        checksum = b'\x00\x00'
        # случайные индентификатор, номер последовательности, данные
        data = b'\x3a\x00\x01\x00make me a sandwhich'
        checksum = ICMP.checksum(type_ + checksum + data)
        return type_ + struct.pack('>H', checksum) + data

    @staticmethod
    def parse(data):
        '''
        Ничего кроме типа и кода нам из сообщения не нужно.
        '''
        return data[0], data[1]

    @staticmethod
    def checksum(data):
        size = len(data)
        checksum = 0
        pointer = 0

        while size > 1:
            checksum += data[pointer]*256 + data[pointer+1]
            size -= 2
            pointer += 2
        if size:
            checksum += 256*data[pointer]

        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += checksum >> 16

        return (~checksum) & 0xFFFF

def is_ip_private(address):
    nums = IP_RE.findall(address)
    for range_ in PRIVATE_IP_RANGES:
        in_range = 0
        for i, num in enumerate(nums):
            if int(num) >= range_[0][i] and int(num) <= range_[1][i]:
                in_range += 1
        if in_range == 4:
            return True
    return False

def whois(address):
    '''
    Сначала обращаемся к DEFAULT_WHOIS_SERVER. Если на нем не оказалось
    информации о стране и автономной системе, спрашиваем refer.
    За имя сети считается доменное имя, получаемое через DNS.
    '''
    country = ''
    a_system = ''
    netname = ''

    whois_server = DEFAULT_WHOIS_SERVER

    while True:
        s = socket.create_connection((whois_server, WHOIS_PORT))

        s.sendall(address.encode('ascii')+b'\r\n')
        answer = bytearray()
        buf = b'stub'
        while buf:
            buf = s.recv(4096)
            answer += buf
        answer = answer.decode('utf8')

        match = COUNTRY_RE.search(answer)
        if match:
            country = match.group(1)
        match = AS_RE.search(answer)
        if match:
            a_system = match.group(1)
        match = NETNAME_RE.search(answer)
        if match:
            netname = match.group(1)
        if a_system and country and netname:
            break
        else:
            #print(answer)
            match = REFERRAL_RE.search(answer)
            #print(match)
            if match:
                whois_server = match.group(1)
            else:
                break

    return a_system, country, netname

def tracert(address, max_ttl):
    '''
    Алгоритм стандартный: увеличиваем TTL не выше max_ttl, пока не
    достигнем назначения.
    '''
    # сокет без протокола транспортного уровня, 1 - номер протокола ICMP в IPv4
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)
    s.settimeout(5)
    packet = ICMP.construct()

    for i in range(1, max_ttl + 1):
        # устанавливаем поле TTL в заголовке IPv4
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, i)
        # порт 0, т.к. протокол транспортного уровня не задействован
        s.sendto(packet, (address, 0))
        try:
            answer, addr = s.recvfrom(1024)
        except socket.timeout:
            yield TraceInfo(i, None)
            continue

        type_, code = ICMP.parse(answer[20:])
        # код 0 и тип 0 - echo reply. Отправляется в случае успешной доставки echo request.
        # В противном случае будет сигнал о истекшем ttl.
        if type_ == 0 and code == 0:
            yield TraceInfo(i, addr[0], True)
            return

        yield TraceInfo(i, addr[0])

def print_trace_info(trace_info):
    if not trace_info.addr:
        print('TTL={}: * * *'.format(trace_info.ttl))
        return

    if is_ip_private(trace_info.addr):
        info = 'private address'
    else:
        info = ', '.join(whois(trace_info.addr))
    print('TTL={}: {} [{}]'.format(trace_info.ttl, trace_info.addr, info))
    if trace_info.is_target:
        print('Destination reached.')

def main():
    parser = argparse.ArgumentParser(
        description='Traceroute + whois.',
        epilog='Usage example: tracert.py 8.8.8.8 e1.ru -m 30'
    )
    parser.add_argument(
        'address', type=str, nargs='+',
        help='addresses that you want to trace')
    parser.add_argument(
        '-m', metavar='max TTL', type=int, default=30,
        help='max TTL. Default: 30'
    )
    args = parser.parse_args()

    for addr in args.address:
        print('Destination address: {} ({})'.format(socket.gethostbyname(addr), addr))
        try:
            for trace_info in tracert(addr, args.m):
                print_trace_info(trace_info)
        except PermissionError:
            print('You do not have enough permissions to perform this action. Use sudo.')
            return
        print()

if __name__ == '__main__':
    main()
