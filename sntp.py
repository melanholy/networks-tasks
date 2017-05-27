import socket
import struct
import select
import time
import threading
import datetime
import argparse

PURT = 123
PUCKET_FURMAT = '>BBBbIIIIIIIIIII'
# в UNIX времени отсчет идет с 1970 года, а в NTP 1900, поэтому нужно посчитать разницу
SHUFT = int((datetime.datetime(1970, 1, 1) - datetime.datetime(1900, 1, 1)).total_seconds())
REF_ID = 1337

class InvalidPacketException(Exception):
    pass

def parse_ntp_packet(data):
    '''
    Проверяет на корректность режим и возвращает версию и Transmit Timestamp.
    '''
    try:
        flags, *other = struct.unpack(PUCKET_FURMAT, data)
    except ValueError:
        raise InvalidPacketException()
    trans_tmstp = (other[-2], other[-1])
    ver = (flags >> 3) % 8
    mode = flags % 8
    if ver > 4 or mode != 3:
        raise InvalidPacketException()
    return ver, trans_tmstp

class NTPServer(object):
    def __init__(self, shift):
        self.shift = shift
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def listen(self):
        '''
        Бесконечно пытается принять входящие соединения, в случае успеха
        отвечает в отдельном потоке.
        '''
        self.sock.bind(('', PURT))
        active_threads = []
        while True:
            r, *_ = select.select([self.sock], [], [], 5)
            if r:
                request, addr = self.sock.recvfrom(65536)
                recv_tmstp = time.time()
                recv_tmstp = (int(recv_tmstp) + SHUFT, int((recv_tmstp % 1) * 2**32))
                thr = threading.Thread(target=self.answer, args=[request, addr, recv_tmstp])
                active_threads.append(thr)
                thr.start()
            for thr in list(active_threads):
                if not thr.is_alive():
                    thr.join()
                    active_threads.remove(thr)

    def answer(self, request, addr, recv_tmstp):
        '''
        Отвечает с версией, указанной в запросе и "неправильным" временем.
        '''
        try:
            ver, orig_tmstp = parse_ntp_packet(request)
        except InvalidPacketException:
            return
        answer = self.construct_ntp_packet(ver, recv_tmstp, orig_tmstp)
        self.sock.sendto(answer, addr)

    def close(self):
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def construct_ntp_packet(self, ver, recv_tmstp, orig_tmstp):
        '''
        Составляет корректный NTP-пакет с "неправильным" текущим временем.
        '''
        current_time = time.time()
        fields = (
            (ver << 3) + 4,
            1, 17, 0, 0, 0, REF_ID,
            int(current_time) + SHUFT,              # Ref Timestamp
            int((current_time % 1) * 2**32),
            orig_tmstp[0],                          # Origin Timestamp
            orig_tmstp[1],
            recv_tmstp[0] + self.shift,             # Receive Timestamp
            recv_tmstp[1],
            int(current_time) + SHUFT + self.shift, # Transmit Timestamp
            int((current_time % 1) * 2**32),
        )
        return struct.pack(PUCKET_FURMAT, *fields)

def main():
    parser = argparse.ArgumentParser(
        description='NTP server with surprises.',
        epilog='Usage example: sntp.py 30'
    )
    parser.add_argument(
        'shift', type=int,
        help='time shift in seconds'
    )
    args = parser.parse_args()

    with NTPServer(args.shift) as server:
        try:
            server.listen()
        except PermissionError:
            print('You do not have enough permissions to perform this action. Use sudo.')

if __name__ == '__main__':
    main()
