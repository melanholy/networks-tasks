'''
5) Вывести список недрузей, упорядоченных по уменьшению числа общих друзей
    vk
'''

import socket
import ssl
import re
import json
import sys
from argparse import ArgumentParser
from collections import defaultdict

CL_RE = re.compile(rb'Content-Length: (\d+)')
API_HOST = 'api.vk.com'
HTTPS_PORT = 443

class APIException(Exception):
    pass

def http_read_response(sock):
    '''
    Считывает http-ответ, в котором есть поле Content-Length.
    '''
    data = bytearray()

    while not CL_RE.search(data):
        data += sock.read(1024)
    length = int(CL_RE.search(data).group(1).decode('ascii'))
    headers_end = data.index(b'\r\n\r\n') + 4
    state = b'Connection: keep-alive' in data

    while len(data) < headers_end + length:
        data += sock.read(1024)

    return data[headers_end:headers_end + length], state

class VkApi(object):
    '''
    Класс для работы api.vk.com.
    More methods coming!(no)
    '''
    def __init__(self):
        self.recreate_sock()

    def get_friends(self, id_):
        '''
        Вызывает метод friends.get из API vk для указанного user_id.
        '''
        args = {'user_id': id_, 'fields': 'domain', 'order': 'random'}
        resp = self.call_method('friends.get', args)
        resp = json.loads(resp.decode('utf-8'))

        if 'error' in resp:
            raise APIException(resp['error']['error_msg'])

        return resp['response']

    def recreate_sock(self):
        '''
        Пересоздает сокет при создании экземпляра или когда хост закрыл
        соединение.
        '''
        self.sock = socket.socket()
        self.sock = ssl.wrap_socket(self.sock)
        self.sock.connect((API_HOST, HTTPS_PORT))

    def call_method(self, method, args):
        '''
        Посылает GET запрос по https на указанный путь указанного
        хоста с указанными параметрами.
        '''
        args = '&'.join(['{}={}'.format(key, val) for key, val in args.items()])
        data = 'GET /method/{}?{} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n'.format(
            method, args, API_HOST
        ).encode('ascii')
        self.sock.send(data)

        resp, state = http_read_response(self.sock)
        if not state:
            self.recreate_sock()

        return resp

    def close(self):
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

def main():
    parser = ArgumentParser(
        description='Print your vk not-friends who you has mutual friends with.',
        epilog='Usage example: api.py 1 20'
    )
    parser.add_argument(
        'user_id', type=int,
        help='user id'
    )
    parser.add_argument(
        '-c', metavar='count', type=int, default=0,
        help='amount of not-friends that will be printed'
    )
    args = parser.parse_args()

    with VkApi() as api:
        try:
            users_friends = api.get_friends(args.user_id)
        except APIException as e:
            print('Error happened:', e, file=sys.stderr)
            return

        friends_ids = [x['user_id'] for x in users_friends]

        mutuals = defaultdict(int)
        for friend in users_friends:
            try:
                friend_friends = api.get_friends(friend['user_id'])
            except APIException:
                continue
            for friend_friend in friend_friends:
                # себя не проверяем, ведь мы не свой друг ;)
                if friend_friend['user_id'] not in friends_ids:
                    name = '{} {}'.format(friend_friend['first_name'], friend_friend['last_name'])
                    mutuals[name] += 1

    chart = sorted(mutuals.items(), key=lambda x: x[1], reverse=True)
    if args.c > 0:
        chart = chart[:args.c]
    for friend_friend in chart:
        print('{}: {} mutual friends'.format(*friend_friend))

if __name__ == '__main__':
    main()
