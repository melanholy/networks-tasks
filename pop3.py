import socket
import ssl
import re
import base64
from argparse import ArgumentParser

HEADER_RE_TEXT = r'(?:(?:^)|(?:\r\n)){}: ([^\r]+)\r\n((?:\s+[^\r]+\r\n)*)'
HEADER_RES = [
    re.compile(HEADER_RE_TEXT.format('Date').encode('ascii')),
    re.compile(HEADER_RE_TEXT.format('To').encode('ascii')),
    re.compile(HEADER_RE_TEXT.format('From').encode('ascii')),
    re.compile(HEADER_RE_TEXT.format('Subject').encode('ascii'))
]
HEADER_TEXT_RE = re.compile(rb'\s*([^\r]+)\r\n')
MIME_RE = re.compile(rb'=\?([^?]+)\?([^?]+)\?([^?]+)\?=')
MIME_SYM_RE = re.compile(rb'=([A-F0-9]{2})')
BOUNDARY_RE = re.compile(rb'--[^\r]+\r\n')
ATTACH_FILENAME = re.compile(
    rb'Content-Disposition: attachment;[^f]+filename="([^"]+)"'
)
WHITESPACE_RE = re.compile(rb'\r\n\s+([^\r\n])')
ATTACH_CONTENT_RE = re.compile(rb'\r\n\r\n([^-]+)(?:--)|(?:$)', flags=re.DOTALL)
DEFAULT_ENCODING = 'utf-8'
SSL_PORT = 995

class POP3Exception(Exception):
    pass

class MailInfo(object):
    def __init__(self, num, from_, to, subject, date, attaches):
        self.num = num
        self.from_ = from_
        self.to = to
        self.subject = subject
        self.date = date
        self.attaches = attaches

def unmime(data):
    '''
    Декодирует байты в MIME формате.
    '''
    res = bytearray(data).replace(b'_', b' ')
    charset = DEFAULT_ENCODING
    while True:
        match = MIME_RE.search(res)
        if not match:
            break
        enc = match.group(2)
        charset = match.group(1).decode('ascii')
        text = bytearray(match.group(3))
        if enc == b'q' or enc == b'Q':
            while True:
                sym = MIME_SYM_RE.search(text)
                if not sym:
                    break
                text[sym.start():sym.end()] = [int(sym.group(1), 16)]
        else:
            text = base64.b64decode(text)
        res[match.start():match.end()] = text
    try:
        res = res.decode(charset)
    except UnicodeDecodeError:
        pass
    return res

def get_attaches(data):
    '''
    Возвращает имена и размеры всех аттачей.
    '''
    matches = list(BOUNDARY_RE.finditer(data))
    files = []
    for idx in range(0, len(matches)):
        if idx < len(matches) - 1:
            text = data[matches[idx].start():matches[idx+1].start()+2]
        else:
            text = data[matches[idx].start():]
        filename = ATTACH_FILENAME.search(text)
        if not filename:
            continue
        filename = WHITESPACE_RE.sub(rb'\1', filename.group(1))
        filename = unmime(filename)
        content = ATTACH_CONTENT_RE.search(text).group(1)
        size = len(base64.b64decode(content.replace(b'\r\n', b'')))
        files.append({'filename': filename, 'size': size})
    return files

def get_main_fields(mail):
    '''
    Извлекает из заголовка поля "От", "Кому", "Тема", "Дата".
    '''
    res = []
    for header_re in HEADER_RES:
        match = header_re.search(mail)
        text = bytearray()
        if match:
            text += match.group(1)
            if match.group(2):
                text += b''.join(
                    [x for x in HEADER_TEXT_RE.findall(match.group(2))]
                )
            text = unmime(text)
        res.append(text)
    return res

class POP3(object):
    '''
    Обертка над протоколом POP3.
    '''
    def __init__(self):
        self.sock = socket.socket()
        self.sock.settimeout(6)
        self.connected = False

    def connect(self, server, port):
        if port == SSL_PORT:
            self.sock = ssl.wrap_socket(self.sock)
        try:
            self.sock.connect((server, port))
        except socket.timeout:
            raise POP3Exception('Не удалось подключиться к серверу: {}'.format(server))

        print(self.sock.recv(1024).decode('ascii'))
        self.connected = True

    def send_and_receive_one_line(self, msg):
        '''
        Отправляет указанную команду, получает многострочный ответ.
        Сигнал конца сообщения - \r\n
        '''
        self.sock.sendall(msg)
        resp = bytearray()
        while True:
            try:
                resp += self.sock.recv(1024)
            except socket.timeout:
                raise POP3Exception('Что-то пошло не так.')
            if resp[-2:] == b'\r\n':
                break

        return resp

    def send_and_receive_multiline(self, msg):
        '''
        Отправляет указанную команду, получает многострочный ответ.
        Сигнал конца сообщения - .\r\n
        '''
        self.sock.sendall(msg)
        resp = bytearray()
        while True:
            try:
                resp += self.sock.recv(1024)
            except socket.timeout:
                raise POP3Exception()
            if resp[-3:] == b'.\r\n':
                break

        return resp

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def auth(self, login, passwd):
        self.send_and_receive_one_line(
            'USER {}\r\n'.format(login).encode('ascii')
        )
        ans = self.send_and_receive_one_line(
            'PASS {}\r\n'.format(passwd).encode('ascii')
        )
        if ans.startswith(b'-ERR'):
            raise POP3Exception('Неверный логин или пароль.')

    def close(self):
        if self.connected:
            self.sock.sendall(b'QUIT\r\n')
        self.sock.close()

    def get_messages(self):
        '''
        Получает последние сообщения при помощи LIST.
        Затем для каждого номера, возвращенного LIST'ом, получает базовую
        информацию о письме с указанным номером.
        '''
        list_ = self.send_and_receive_multiline(b'LIST\r\n')
        for line in list_.split(b'\r\n')[1:-2]:
            num = int(line.split(b' ')[0])
            mail = self.send_and_receive_multiline(
                'RETR {}\r\n'.format(num).encode('ascii')
            )
            date, to, from_, subj = get_main_fields(mail)
            attaches = get_attaches(mail)
            yield MailInfo(num, from_, to, subj, date, attaches)

def print_mailinfo(mail):
    print('Msg #{}:'.format(mail.num))
    print('    Date: {}'.format(mail.date))
    print('    To: {}'.format(mail.to))
    print('    From: {}'.format(mail.from_))
    print('    Subject: {}'.format(mail.subject))
    print('    Attachments: {}'.format(len(mail.attaches)))
    for attach in mail.attaches:
        print('        {}, {} bytes'.format(
            attach['filename'], attach['size']
        ))
    print('-'*40)

def main():
    parser = ArgumentParser(
        description='POP3 client. Only prints basic info about new messages.',
        epilog='Usage example: pop3.py pop.gmail.com 995 admin password'
    )
    parser.add_argument('server', type=str, help='POP3 server to connect')
    parser.add_argument('port', type=int, help='Port of POP3 server')
    parser.add_argument('username', type=str, help='POP3 username')
    parser.add_argument('password', type=str, help='POP3 password')
    args = parser.parse_args()

    with POP3() as pop3:
        try:
            pop3.connect(args.server, args.port)
            pop3.auth(args.username, args.password)
            for mail in pop3.get_messages():
                print_mailinfo(mail)
        except POP3Exception as e:
            print('ERROR: {}'.format(e))

if __name__ == '__main__':
    main()
