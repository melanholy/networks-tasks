import socket
import re
import select
from threading import Thread
from argparse import ArgumentParser

HOST_RE = re.compile(rb'Host: ([^\r:]+)(?::(\d+))?\r\n')
CL_RE = re.compile(rb'Content-Length: (\d+)\r\n')
NOT_IMPL_MSG = b'HTTP/1.1 501 Not Implemented\r\n\r\n'
HTTP_DEFAULT_PORT = 80

def recv_msg_with_content_length(sock, head):
    '''
    Получает plain-text сообщение.
    '''
    content_len = int(CL_RE.search(head).group(1).decode('ascii'))
    while b'\r\n\r\n' not in head:
        head += sock.recv(1024)
    content_start = head.index(b'\r\n\r\n') + 4
    while len(head) - content_start != content_len:
        head += sock.recv(1024)

def receive_request(conn):
    '''
    Получает клиентский запрос, который нужно переправить хосту.
    '''
    msg = bytearray()
    while len(msg) < 4:
        msg += conn.recv(1024)
    if msg.startswith(b'GET') or msg.startswith(b'HEAD'):
        while not msg.endswith(b'\r\n\r\n'):
            msg += conn.recv(1024)
    elif msg.startswith(b'POST'):
        while b'Content-Length' not in msg:
            msg += conn.recv(1024)
        recv_msg_with_content_length(conn, msg)
    else:
        return None

    return msg

def receive_answer(conn):
    '''
    Получает ответ от хоста.
    '''
    ans = bytearray()
    while b'Content-Length:' not in ans and \
        b'Transfer-Encoding: chunked' not in ans and \
        b'Not Modified' not in ans:
        ans += conn.recv(1024)
    if b'Not Modified' in ans:
        while not ans.endswith(b'\r\n'):
            ans += conn.recv(1024)
    elif b'Content-Length:' in ans:
        recv_msg_with_content_length(conn, ans)
    elif b'Transfer-Encoding: chunked' in ans:
        while not ans.endswith(b'\r\n0\r\n\r\n'):
            ans += conn.recv(1024)
    else:
        return None

    return ans

def process_connection(client_sock):
    '''
    Перенаправляет запрос на хост и возвращает ответ клиенту.
    '''
    with client_sock:
        try:
            msg = receive_request(client_sock)
            if not msg:
                client_sock.send(NOT_IMPL_MSG)
                return
            match = HOST_RE.search(msg)
            host = socket.gethostbyname(match.group(1).decode('ascii'))
            port = HTTP_DEFAULT_PORT
            if match.group(2):
                port = int(match.group(2))

            with socket.socket() as host_sock:
                host_sock.settimeout(3)
                host_sock.connect((host, port))
                host_sock.sendall(msg)
                ans = receive_answer(host_sock)

            if ans:
                client_sock.sendall(ans)
            else:
                client_sock.send(NOT_IMPL_MSG)
        except (socket.timeout, ConnectionRefusedError):
            pass

def main():
    parser = ArgumentParser(description='Proxy server with bugs.')
    parser.add_argument(
        '-l', metavar='bind_port', type=int, default=54123,
        help='A port listening socket will bind to. Default: 54123'
    )
    args = parser.parse_args()

    sock = socket.socket()
    sock.bind(('', args.l))
    sock.listen(3)

    active_threads = []
    with sock:
        while True:
            r, *_ = select.select([sock], [], [], 5)
            if r:
                conn, _ = sock.accept()
                conn.settimeout(3)
                thr = Thread(target=process_connection, args=[conn])
                thr.daemon = True
                active_threads.append(thr)
                thr.start()
            for thr in list(active_threads):
                if not thr.is_alive():
                    thr.join()
                    active_threads.remove(thr)

if __name__ == '__main__':
    main()
