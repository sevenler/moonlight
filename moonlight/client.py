import socket
import selectors
from logger import logger

SOCK_V5 = chr(0x05)
BUFFER_SIZE = 1024

ATYPE_IP_V4 = chr(0x01)
ATYPE_DOMAINNAME = chr(0x03)
ATYPE_IP_V6 = chr(0x04)

CMD_CONNECT = chr(0x01)

AUTH_METHODS_LIST = [chr(0x0), chr(0x1), chr(0x2), chr(0x3), chr(0x80), chr(0xFF)]
AUTH_METHOD = chr(0x0)

P_S_NONE = 0
P_S_AUTH_WAITING = 1
P_S_AUTHED = 2
P_S_CONNECTED = 3

class _ProxyRequestHandler(object):
    def __init__(self, socket, selector):
        self._l_socket = socket
        self._fd = socket.fileno()
        self._selector = selector
        self._selector.register(socket, selectors.EVENT_READ, self._handle_request)
        self._status = P_S_NONE
        self._s_socket = None

    def _handle_request(self, sock, mask):
        if self._status == P_S_NONE:
            self._auth_check()
        elif self._status ==  P_S_AUTH_WAITING:
            self._auth()
        elif self._status == P_S_AUTHED:
            self._connect()
        else:
            self._transmit()

    def __set_status(self, status):
        self._status = status

    def _auth(self):
        pass

    def _auth_check(self):
        data = self._l_socket.recv(BUFFER_SIZE)
        if data[0] != SOCK_V5:
            logger.error('Error socket type')
            self._close_connect()

        num_methods = ord(data[1])
        methods = [data[i+2] for i in range(num_methods)]
        if AUTH_METHOD in methods:
            if AUTH_METHOD == AUTH_METHODS_LIST[0]:
                logger.info('Checked socket5 auth, set authed.[%s]'%(self._fd))
                self.__set_status(P_S_AUTHED)
            else:
                self.__set_status(P_S_AUTH_WAITING)
                logger.info('Checked socket5 auth, set auth waiting.[%s]'%(self._fd))
            msg = '%s%s'%(SOCK_V5, AUTH_METHOD)
            self._l_socket.send(msg)
        else:
            logger.error('Error auth type')
            self._close_connect()

    def _connect(self):
        data = self._l_socket.recv(BUFFER_SIZE)
        if data[0] != SOCK_V5:
            logger.error('Error socket type')
            self._close_connect()

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
        sock_name = self._l_socket.getsockname()
        local_address = socket.inet_aton(sock_name[0])
        int_port = sock_name[1]
        local_port = chr(int_port / 256) + chr(int_port % 256)

        if cmd == CMD_CONNECT:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._s_socket = server_sock
            try:
                print(server_address, server_port)
                server_sock.connect((server_address, server_port))
                send_msg = '%s\x00\x00\x01%s%s'%(SOCK_V5, local_address,
                                                 local_port)
                self._l_socket.send(send_msg)
                self.__set_status(P_S_CONNECTED)

                def handle_transmit(sock, mask):
                    up_stream = None
                    if sock == self._l_socket:
                        up_stream = True
                    elif sock == self._s_socket:
                        up_stream = False
                    else:
                        logger.error('Error socket')
                        self._close_connect()
                    self._transmit(up_stream)

                self._selector.unregister(self._l_socket)
                self._selector.register(self._l_socket, selectors.EVENT_READ,
                                        handle_transmit)
                self._selector.register(self._s_socket, selectors.EVENT_READ,
                                        handle_transmit)
                logger.info('connected to (%s:%s) with command %s. [%s]'%\
                            (server_address, server_port, cmd, self._fd))
            except Exception as e:
                logger.error(e)
                import traceback, sys
                traceback.print_exc(file=sys.stdout)
                send_msg = '%s\x01\x00\x01%s%s'%(SOCK_V5, local_address, local_port)
                self._l_socket.send(send_msg)
                self._close_connect()

        else:
            logger.error('Error connection type')
            self._close_connect()

    def _transmit(self, is_up_stream):
        if is_up_stream:
            data = self._l_socket.recv(BUFFER_SIZE)
            self._s_socket.send(data)
        else:
            data = self._s_socket.recv(BUFFER_SIZE)
            self._l_socket.send(data)

    def _close_connect(self):
        logger.info('closeing connect.[%s]'%(self._fd))
        if self._l_socket is not None:
            self._l_socket.close()
        if self._s_socket is not None:
            self._s_socket.close()


class Socket5Proxy(object):
    def __init__(self, config):
        self._config = config
        self._load_config()
        self._stoping = False
        self._connection_handlers = {}

    def _load_config(self):
        conf = self._config
        self._local_address = conf['local_address']
        self._local_port = int(conf['local_port'])

        self._l_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._l_socket.bind((self._local_address, self._local_port))
        self._l_socket.listen(5)
        self._l_socket.setblocking(0)

        self._selector = selectors.DefaultSelector()
        def _handle_accept(sock, mask):
            conn, address = sock.accept()
            conn.setblocking(0)

            logger.info('get connection from (%s:%s)'%(address[0], address[1]))
            handler = _ProxyRequestHandler(conn, self._selector)
            self._connection_handlers[conn] = handler
        self._selector.register(self._l_socket, selectors.EVENT_READ, _handle_accept)

    def run(self):
        logger.info('run socket5 proxy on (%s:%s)'%(self._local_address, self._local_port))
        while not self._stoping:
            events = self._selector.select()
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)

    def stop(self):
        self._stoping = True
        self._l_socket.close()
        for k, handler in self._connection_handlers:
            handler.close()

if __name__ == '__main__':
    conf = {
        'local_address': '127.0.0.1',
        'local_port': 1235,
    }
    Socket5Proxy(config=conf).run()
