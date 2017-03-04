import socket

import selectors
from logger import logger

BUFFER_SIZE = 1024

ATYPE_IP_V4 = chr(0x01)
ATYPE_DOMAINNAME = chr(0x03)
ATYPE_IP_V6 = chr(0x04)

CMD_CONNECT = chr(0x01)


class _RequestRelayHandler(object):
    def __ini__(self, conn, selector):
        self._conn = conn
        self._fd = conn.fileno()
        self._selector = selector
        self._selector.register(conn, selectors.EVENT_READ, self.__handle_connection)
        self._remote_socket = None

    def __handle_connection(self, socks, mask):
        data = socks.revc(BUFFER_SIZE)

        cmd = data[1]
        address_type = data[3]
        address = None
        if address_type == ATYPE_IP_V4:
            address = socket.inet_ntoa(data[4:8])
        elif address_type == ATYPE_DOMAINNAME:
            address = socket.gethostbyname(data[5:5 + ord(data[4])])
        elif address_type == ATYPE_IP_V6:
            address = data[4:8]
        else:
            logger.error('Error address type')
            self._close_connect()
        port = ord(data[-2]) * 256 + ord(data[-1])
        logger.info('begin to connecting (%s:%s) with command %s. [%s]'\
                    %(address, port, cmd, self._fd))
        self.__connect_remote(cmd, address, port)

    def __connect_remote(self, cmd, server_address, server_port):
        sock_name = self._conn.getsockname()
        local_address = socket.inet_aton(sock_name[0])
        int_port = sock_name[1]
        local_port = chr(int_port / 256) + chr(int_port % 256)

        if cmd == CMD_CONNECT:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._remote_socket = server_sock
            try:
                server_sock.connect((server_address, server_port))
                send_msg = '\x00%s%s'%(local_address, local_port)
                self._conn.send(send_msg)

                def handle_relay(sock, mask):
                    up_stream = None
                    if sock == self._l_socket:
                        up_stream = True
                    elif sock == self._s_socket:
                        up_stream = False
                    else:
                        logger.error('Error socket')
                        self._close_connect()
                    self._relay(up_stream)

                self._selector.unregister(self._conn)
                self._selector.register(self._conn, selectors.EVENT_READ,
                                        handle_relay)
                self._selector.register(self._remote_socket, selectors.EVENT_READ,
                                        handle_relay)
                logger.info('connected to (%s:%s) with command %s. [%s]'%\
                            (server_address, server_port, cmd, self._fd))
            except Exception as e:
                logger.error(e)
                import traceback, sys
                traceback.print_exc(file=sys.stdout)
                send_msg = '\x01%s%s'%(local_address, local_port)
                self._conn.send(send_msg)
                self._close_connect()
        else:
            logger.error('Error connection type')
            self._close_connect()

    def _relay(self, up_stream):
        if up_stream:
            data = self._conn.recv(BUFFER_SIZE)
            self._remote_socket.send(data)
        else:
            data = self._remote_socket.recv(BUFFER_SIZE)
            self._conn.send(data)

    def _close_connect(self):
        logger.info('closeing connect.[%s]'%(self._fd))
        if self._conn is not None:
            self._conn.close()
        if self._remote_socket is not None:
            self._remote_socket.close()

class Server(object):
    def __init__(self, conf):
        self._conf = conf
        self._stoping = False
        self._load_conf()

    def _load_conf(self):
        self._address = self._conf['address']
        self._port= self._conf['port']

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self._address, self._port))
        sock.listen(5)
        sock.setblocking(0)
        self._socket = sock
        self._selector = selectors.DefaultSelector()
        self._selector_handlers = {}
        def _handle_accept(sock, mask):
            conn, address = sock.accept()
            conn.setblocking(0)

            logger.info('get connection from (%s:%s)'%(address[0], address[1]))
            handler = _RequestRelayHandler(conn, self._selector)
            self._connection_handlers[conn] = handler
        self._selector.register(self._socket, selectors.EVENT_READ, _handle_accept)

    def run(self):
        logger.info('run socket5 server on (%s:%s)'%(self._address, self._port))
        while not self._stoping:
            events = self._selector.select()
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)

    def stop(self):
        self._stoping = True


if __name__ == '__main__':
    conf = {
        'local_address': '127.0.0.1',
        'local_port': 8889,
    }
    Server(config=conf).run()
