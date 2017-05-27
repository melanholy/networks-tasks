import socket
import ssl
import sys
import glob
import os.path
import re
from argparse import ArgumentParser
from base64 import b64encode

EHLO = 'oleg.oleg'
DEFAULT_FROM = 'oleg@mail.ru'
PICTURE_EXTENSIONS = ['/*.png', '/*.jpg', '/*.bmp']
SSL_PORT = 465
BOUNDARY = 'Oleg'
SIZE_RE = re.compile(rb'SIZE[^\d]+(\d+)')

class SMTPException(Exception):
    pass

def log(preamble, msg):
    if isinstance(msg, bytes) or isinstance(msg, bytearray):
        msg = msg.decode('utf8')
    sys.stderr.write(preamble)
    if msg.endswith('\r\n'):
        msg = msg[:-2]
    sys.stderr.write(
        msg.replace('\r\n', '\r\n'+' '*len(preamble))
    )
    sys.stderr.write('\r\n')

class Smtp(object):
    '''
    Обертка над протоколом SMTP.
    '''
    def __init__(self):
        self.sock = socket.socket()
        self.sock.settimeout(3)
        self.helo = None
        self.connected = False

    def connect(self, addr, port):
        '''
        Подключается и шлет EHLO. Если есть возможность, устанавливает
        защищенное соединение.
        '''
        if port == SSL_PORT:
            self.sock = ssl.wrap_socket(self.sock)
        try:
            self.sock.connect((addr, port))
        except socket.timeout:
            raise SMTPException('Couldn\'t connect to {}:{}'.format(addr, port))
        log('s: ', self.sock.recv(1024))
        ans = self.ehlo()
        if b'STARTTLS' in ans:
            ans = self.send_and_receive_one_line(b'STARTTLS\r\n')
            self.sock = ssl.wrap_socket(self.sock)
            ans = self.ehlo()
            log('s: ', ans)
        self.helo = ans
        self.connected = True

    def ehlo(self):
        ehlo = 'EHLO {}\r\n'.format(EHLO).encode('utf8')
        log('c: ', ehlo)
        self.sock.send(ehlo)
        ans = bytearray()
        while not ans or not ans.split(b'\r\n')[-2][3] != b' ':
            ans += self.sock.recv(1024)

        log('s: ', ans)
        return ans

    def auth_login(self, login, password):
        '''
        Авторизуется используя команду AUTH LOGIN.
        '''
        self.send_and_receive_one_line(b'AUTH LOGIN\r\n')
        ans = self.send_and_receive_one_line(
            b64encode(login.encode('utf8')) + b'\r\n'
        )
        if not ans.startswith(b'334'):
            raise SMTPException('Wrong login or password')
        ans = self.send_and_receive_one_line(
            b64encode(password.encode('utf8')) + b'\r\n'
        )
        if not ans.startswith(b'235'):
            raise SMTPException('Wrong login or password')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        if self.connected:
            self.send_and_receive_one_line(b'QUIT\r\n')
        self.sock.close()

    def auth_plain(self, login, password):
        '''
        Авторизуется используя команду AUTH PLAIN.
        '''
        encoded = b64encode('\0{}\0{}'.format(login, password).encode('utf8'))
        ans = self.send_and_receive_one_line('AUTH PLAIN {}\r\n'.format(encoded).encode('utf8'))
        if not ans.startswith(b'235'):
            raise SMTPException('Wrong login or password')

    def send_and_receive_one_line(self, msg, log_send=True):
        '''
        Отправляет указанную команду, получает ответ.
        Сигнал конца сообщения - \r\n
        '''
        if log_send:
            log('c: ', msg)

        self.sock.sendall(msg)
        resp = bytearray()
        while True:
            resp += self.sock.recv(1024)
            if resp[-2:] == b'\r\n':
                break

        log('s: ', resp)
        return resp

    def auth(self, login, password):
        '''
        Пытается авторизоваться одним из доступных способов: PLAIN или LOGIN.
        '''
        if b'LOGIN' in self.helo:
            self.auth_login(login, password)
        elif b'PLAIN' in self.helo:
            self.auth_plain(login, password)
        else:
            raise SMTPException('Server doesn\'t support LOGIN and PLAIN commands')

    @staticmethod
    def construct_message(from_, to, pictures):
        msg = []
        msg.append(b'\r\n'.join([
            'From: Oleg <{}>'.format(from_).encode('ascii'),
            'To: Oleg <{}>'.format(to).encode('ascii'),
            'Subject: {}'.format(BOUNDARY).encode('ascii'),
            'Content-Type: multipart/related; boundary={}'.format(BOUNDARY).encode('ascii'),
            b'',
            b'',
            '--{}'.format(BOUNDARY).encode('ascii'),
            b'Content-Type: text/html; charset=ascii',
            b'',
            b'Oleg',
            b''
        ]))
        for pic_data, filename in pictures:
            msg.append(b'\r\n'.join([
                '--{}'.format(BOUNDARY).encode('ascii'),
                'Content-Type: image/{}'.format(filename.split('.')[-1]).encode('utf8'),
                b'Content-Transfer-Encoding: base64',
                'Content-Disposition: attachment; filename="{}"'.format(filename).encode('utf8'),
                b'',
                b64encode(pic_data),
                b''
            ]))
        msg.append('--{}--\r\n.\r\n'.format(BOUNDARY).encode('ascii'))
        return b''.join(msg)

    def send_message(self, from_, to, pictures):
        '''
        Отсылает все полученные изображения на указанную почту.
        '''
        message = Smtp.construct_message(from_, to, pictures)
        match = SIZE_RE.search(self.helo)
        if match:
            max_size = int(match.group(1).decode('ascii'))
            if len(message) > max_size:
                raise SMTPException('Message too long. Maximum length: {}'.format(max_size))
        self.send_and_receive_one_line(
            'MAIL FROM: <{}>\r\n'.format(from_).encode('ascii')
        )
        self.send_and_receive_one_line(
            'RCPT TO: <{}>\r\n'.format(to).encode('ascii')
        )
        self.send_and_receive_one_line(b'DATA\r\n')
        self.send_and_receive_one_line(message, False)

def main():
    parser = ArgumentParser(
        description='SMTP client. Only sends pictures from given directory.',
        epilog='Usage example: smtp.py smtp.gmail.com 465 ~/oleg oleg oleg'
    )
    parser.add_argument('server', type=str, help='SMTP server to connect')
    parser.add_argument('port', type=int, help='Port of SMTP server')
    parser.add_argument('recipient', type=str, help='To whom send mail')
    parser.add_argument('directory', type=str, help='Directory with pictures')
    parser.add_argument(
        '-s', metavar='sender', type=str, default=DEFAULT_FROM,
        help='From whom send mail. Ignored if username is set. Default: oleg@mail.ru'
    )
    parser.add_argument('-u', metavar='username', type=str, help='SMTP username')
    parser.add_argument('-p', metavar='password', type=str, help='SMTP password')
    args = parser.parse_args()

    pictures = []
    for ext in PICTURE_EXTENSIONS:
        for picture in glob.glob(args.directory + ext):
            with open(picture, 'rb') as f:
                data = f.read()
            pictures.append((data, os.path.basename(picture)))

    smtp = Smtp()

    with Smtp() as smtp:
        try:
            smtp.connect(args.server, args.port)
            from_ = args.s
            if args.u and args.p:
                from_ = args.u
                smtp.auth(args.u, args.p)
            smtp.send_message(from_, args.recipient, pictures)
        except SMTPException as e:
            print('ERROR:', e)

if __name__ == '__main__':
    main()
