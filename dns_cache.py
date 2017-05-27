import socket
import select
import time
import random
import struct
import sys
from argparse import ArgumentParser
from io import BytesIO

DNS_PORT = 53
MAX_UDP_PACKET_LENGTH = 65536

class DnsError(Exception):
    pass

class ResourceRecord(object):
    '''
    Ресурсная запись некоторого домена.
    '''
    def __init__(self, name, type_, class_, ttl, data):
        self.creation = time.time()
        self._ttl = ttl
        self.data = data
        self.name = name
        self.type_ = type_
        self.class_ = class_

    @property
    def ttl(self):
        return int(self._ttl - (time.time() - self.creation))

class Question(object):
    def __init__(self, qname, type_, class_):
        self.qname = qname
        self.type_ = type_
        self.class_ = class_

    def __hash__(self):
        return hash(self.qname) + hash(self.type_) + hash(self.class_)

    def __eq__(self, other):
        return self.qname == other.qname and \
            self.type_ == other.type_ and self.class_ == other.class_

class Counter(object):
    '''
    Класс для подсчета чего-то, произошедшего с даты создания
    экземпляра этого класса.
    '''
    def __init__(self):
        self.count = 0
        self.time = time.time()

def read_qname(stream, query):
    '''
    Читает доменное имя из пакета DNS.
    '''
    code = stream.read(1)[0]
    if not code:
        return b''
    if code >= 192:
        # вместо доменного имя указатель на место в запросе, в котором
        # написано нужное доменное имя
        stream = BytesIO(query[stream.read(1)[0]:])
        return read_qname(stream, query)

    res = bytearray()
    res += stream.read(code)
    res += b'.' + read_qname(stream, query)

    return bytes(res)

def read_answer(stream, query):
    '''
    Читает ответную DNS запись
    '''
    name = read_qname(stream, query)
    type_, class_, ttl, data_len = struct.unpack('>HHIH', stream.read(10))
    data = stream.read(data_len)
    return ResourceRecord(name, type_, class_, ttl, data)

def parse_dns_packet(data, query):
    stream = BytesIO(data)
    id_, _, q_count, an_count, ns_count, ar_count = struct.unpack('>HHHHHH', stream.read(12))

    questions = []
    for _ in range(q_count):
        qname = read_qname(stream, query)
        type_, class_ = struct.unpack('>HH', stream.read(4))
        questions.append(Question(qname, type_, class_))

    an_recs = []
    ns_recs = []
    ar_recs = []

    for _ in range(an_count):
        rec = read_answer(stream, query)
        an_recs.append(rec)
    for _ in range(ns_count):
        rec = read_answer(stream, query)
        ns_recs.append(rec)
    for _ in range(ar_count):
        rec = read_answer(stream, query)
        an_recs.append(rec)

    return id_, questions, (an_recs, ns_recs, ar_recs)

def construct_dns_packet(id_, opcode, questions, answers):
    id_ = struct.pack('>H', id_)
    flags = struct.pack('>H', (opcode << 15) + (1 << 8) + (1 << 7))
    q_count = struct.pack('>H', len(questions))
    counts = struct.pack('>HHH', len(answers[0]), len(answers[1]), len(answers[2]))

    data = bytearray()
    for question in questions:
        for x in question.qname.split(b'.'):
            data += struct.pack('>B', len(x)) + x
        data += struct.pack('>HH', question.type_, question.class_)

    for answer in answers:
        for record in answer:
            for x in record.name.split(b'.'):
                data += struct.pack('>B', len(x)) + x
            data += struct.pack('>HHIH', record.type_, record.class_, record.ttl, len(record.data))
            data += record.data

    return b''.join([id_, flags, q_count, counts, data])

class Server(object):
    '''
    Класс для DNS-сервера. Умеет отвечать на корректные запросы,
    кэшировать ответы, а также определять жуликов и злоумышленников.
    '''
    def __init__(self, master_addr, master_port, listen_port, timeout):
        self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_sock.bind(('', listen_port))
        self.cache = {}
        self.timeout = timeout
        self.master_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.master_sock.settimeout(self.timeout)
        self.master = (master_addr, master_port)
        self.query_history = {}

    def __enter__(self):
        return self

    def close(self):
        self.client_sock.close()
        self.master_sock.close()

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def resolve(self, questions):
        '''
        Пытается получить ответ по полученному запросу.
        Все что есть в кэше берет оттуда, за остальным обращается к мастеру.
        '''
        answers = [] # все ответы
        to_master = [] # записи, которых нет в кэше
        for question in questions:
            if question in self.cache:
                cached = self.cache[question]
                for answer in cached:
                    if len(answer) != len([x for x in answer if x.ttl > 0]):
                        del self.cache[question]
                        break
                else:
                    print('({}, {}, {}) was in cache.'.format(
                        question.qname, question.type_, question.class_
                    ))
                    answers.extend(cached)
                    continue
            to_master.append(question)
            print('Asking master-server about ({}, {}, {})'.format(
                question.qname, question.type_, question.class_
            ))

        if not to_master:
            return answers

        for question in to_master:
            id_ = random.randint(0, 65000)
            query = construct_dns_packet(id_, 0, [question], ([], [], []))
            self.master_sock.sendto(query, self.master)
            try:
                answer, _ = self.master_sock.recvfrom(MAX_UDP_PACKET_LENGTH)
            except socket.timeout:
                raise DnsError(
                    'Master-server didn\'t answer after {} seconds.'.format(self.timeout)
                )
            ans_id, _, answer_records = parse_dns_packet(answer, query)
            if id_ != ans_id:
                raise DnsError('Incorrect answer from master-server.')
            self.cache[question] = answer_records
            answers.extend(answer_records)

        return answers

    def answer(self, query_packet, addr):
        '''
        Проверяет, не шлет ли клиент слишком много пакетов.
        Если все нормально, "резолвит" запрос и отсылает ответ клиенту.
        '''
        query_id = (query_packet[2:], addr[0])
        if query_id in self.query_history:
            counter = self.query_history[query_id]
            counter.count += 1
            if time.time() - counter.time < 180 and counter.count > 6:
                # не ответаем тем кто шлет слишком много одинаковых запросов
                raise DnsError('{} sends too many identical queries.'.format(*addr))
        else:
            counter = Counter()
            self.query_history[query_id] = counter
            counter.count += 1

        id_, questions, _ = parse_dns_packet(query_packet, None)
        answers = self.resolve(questions)
        answer_packet = construct_dns_packet(id_, 1, questions, answers)
        self.client_sock.sendto(answer_packet, addr)

    def mainloop(self):
        '''
        Бесконечно ожидает запросов, по мере их поступления отвечает.
        '''
        while True:
            r, *_ = select.select([self.client_sock], [], [], 5)
            for key, val in dict(self.query_history).items():
                if time.time() - val.time > 180:
                    del self.query_history[key]
            if r:
                query, addr = self.client_sock.recvfrom(MAX_UDP_PACKET_LENGTH)
                print('sfsdf')
                print('Got query from {}:{}'.format(*addr))
                try:
                    self.answer(query, addr)
                except DnsError as e:
                    print(e)

def main():
    parser = ArgumentParser(
        description='Caching DNS-server. Only work as forwarder.',
        epilog='Usage example: dns_cache.py 8.8.8.8'
    )
    parser.add_argument(
        'server', type=str,
        help='other DNS-server to which all incoming messages will be forwarded'
    )
    parser.add_argument(
        '-p', metavar='server port', type=int,
        help='port of other DNS-server. Default: 53', default=DNS_PORT
    )
    parser.add_argument(
        '-l', metavar='listen port', type=int,
        help='a port on which server will be listening to incoming messages. Default: 53',
        default=DNS_PORT
    )
    parser.add_argument(
        '-t', metavar='timeout', type=int,
        help='for how long to wait for an answer. Time in seconds. Default: 5',
        default=5
    )
    args = parser.parse_args()
    try:
        server = Server(args.server, args.p, args.l, args.t)
    except PermissionError:
        print('You do not have enough permissions to do this. Use sudo.', file=sys.stderr)
        return
    except OSError as e:
        print(e)
        print('Server start failed. Closing.', file=sys.stderr)
        return

    print('Server started.')
    with server:
        try:
            server.mainloop()
        except KeyboardInterrupt:
            print('Server has been shut off.')

if __name__ == '__main__':
    main()
