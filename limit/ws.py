import socket, threading, select, signal, sys, time, getopt, os
import base64, hashlib

# Listen
LISTENING_ADDR = '127.0.0.1'
LISTENING_PORT = int(os.environ.get('WS_PORT', '10015'))

# Passwd
PASS = ''

# CONST
BUFLEN = 4096 * 4
TIMEOUT = 3600
DEFAULT_HOST = os.environ.get('WS_TARGET', '127.0.0.1:2222')
MAP_FILE = os.environ.get('WS_SSH_MAP', '/run/ws-ssh.map')
MAP_TTL = 86400
MAP_LOCK = threading.Lock()
WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'


def valid_ip(value):
    value = (value or '').strip()
    if value.startswith('[') and value.endswith(']'):
        value = value[1:-1]
    value = value.split('%')[0]
    if not value:
        return ''
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, value)
            return value
        except OSError:
            pass
    return ''


def prune_map(now):
    try:
        if not os.path.exists(MAP_FILE):
            return
        keep = []
        with open(MAP_FILE, 'r', errors='ignore') as handle:
            for line in handle:
                parts = line.split()
                if len(parts) != 3:
                    continue
                try:
                    stamp = int(parts[0])
                except ValueError:
                    continue
                if now - stamp <= MAP_TTL:
                    keep.append(line if line.endswith('\n') else line + '\n')
        tmp = MAP_FILE + '.tmp'
        with open(tmp, 'w') as handle:
            handle.writelines(keep)
        os.replace(tmp, MAP_FILE)
    except Exception:
        pass


def record_map(local_port, real_ip):
    now = int(time.time())
    line = '%d %d %s\n' % (now, local_port, real_ip)
    with MAP_LOCK:
        try:
            if os.path.exists(MAP_FILE) and os.path.getsize(MAP_FILE) > 262144:
                prune_map(now)
            fd = os.open(MAP_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
            try:
                os.write(fd, line.encode('utf-8'))
            finally:
                os.close(fd)
        except Exception as exc:
            print('map error: ' + str(exc))


class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
        self.threadsLock = threading.Lock()
        self.logLock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        intport = int(self.port)
        self.soc.bind((self.host, intport))
        self.soc.listen(0)
        self.running = True

        try:
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue

                conn = ConnectionHandler(c, self, addr)
                conn.start()
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()

    def printLog(self, log):
        self.logLock.acquire()
        print(log)
        self.logLock.release()

    def addConn(self, conn):
        try:
            self.threadsLock.acquire()
            if self.running:
                self.threads.append(conn)
        finally:
            self.threadsLock.release()

    def removeConn(self, conn):
        try:
            self.threadsLock.acquire()
            self.threads.remove(conn)
        finally:
            self.threadsLock.release()

    def close(self):
        try:
            self.running = False
            self.threadsLock.acquire()

            threads = list(self.threads)
            for c in threads:
                c.close()
        finally:
            self.threadsLock.release()


class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = b''
        self.server = server
        self.real_ip = valid_ip(addr[0]) or '127.0.0.1'
        self.target_port = 0
        self.method = 'CONNECT'
        self.log = 'Connection: ' + str(addr) + ' (' + self.real_ip + ')'

    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True

        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)

            # Decode for header searching
            try:
                buffer_str = self.client_buffer.decode('utf-8', errors='ignore')
            except:
                buffer_str = ''

            # Trust X-Real-IP / X-Forwarded-For only from the local nginx.
            try:
                peer_ip = self.client.getpeername()[0]
            except:
                peer_ip = ''
            if peer_ip.startswith('127.') or peer_ip == '::1':
                header_ip = valid_ip(self.findHeader(buffer_str, 'X-Real-IP'))
                if not header_ip:
                    forwarded = self.findHeader(buffer_str, 'X-Forwarded-For')
                    if forwarded:
                        header_ip = valid_ip(forwarded.split(',')[0])
                if header_ip:
                    self.real_ip = header_ip
                    self.log = 'Connection: ' + str(peer_ip) + ' (' + self.real_ip + ')'

            hostPort = self.findHeader(buffer_str, 'X-Real-Host')
            if hostPort == '' or not (hostPort.startswith('127.0.0.1') or hostPort.startswith('localhost')):
                hostPort = DEFAULT_HOST
            elif ':' not in hostPort:
                # X-Real-Host without a port: use the target's port, not 443.
                hostPort = hostPort + ':' + DEFAULT_HOST.rsplit(':', 1)[-1]

            split = self.findHeader(buffer_str, 'X-Split')
            if split != '':
                self.client.recv(BUFLEN)

            passwd = self.findHeader(buffer_str, 'X-Pass')
            if len(PASS) != 0 and passwd != PASS:
                self.client.send(b'HTTP/1.1 400 WrongPass!\r\n\r\n')
            elif len(PASS) != 0 or hostPort != '':
                self.method_CONNECT(hostPort, buffer_str)
            else:
                print('- No X-Real-Host!')
                self.client.send(b'HTTP/1.1 400 NoXRealHost!\r\n\r\n')

        except Exception as e:
            self.log += ' - error: ' + str(e)
            self.server.printLog(self.log)
            pass
        finally:
            self.close()
            self.server.removeConn(self)

    def findHeader(self, head, header):
        low = head.lower()
        key = header.lower()
        aux = low.find(key + ': ')
        if aux == -1:
            # tolerate headers without a space after the colon
            aux = low.find(key + ':')
            if aux == -1:
                return ''
            start = low.find(':', aux) + 1
        else:
            start = low.find(':', aux) + 2

        end = head.find('\r\n', start)
        if end == -1:
            return ''
        return head[start:end].strip()

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i + 1:])
            host = host[:i]
        else:
            if self.method == 'CONNECT':
                port = 443
            else:
                port = LISTENING_PORT

        (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]

        self.target = socket.socket(soc_family, soc_type, proto)
        self.targetClosed = False
        self.target.connect(address)
        self.target_port = port

    def method_CONNECT(self, path, request=''):
        self.log += ' - CONNECT ' + path
        self.connect_target(path)

        key = self.findHeader(request, 'Sec-WebSocket-Key')
        if key:
            accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
            response = ('HTTP/1.1 101 Switching Protocols\r\n'
                        'Upgrade: websocket\r\n'
                        'Connection: Upgrade\r\n'
                        'Sec-WebSocket-Accept: ' + accept + '\r\n\r\n').encode()
        else:
            response = b'HTTP/1.1 101 Dragon Emperor Tunneling\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'

        self.client.sendall(response)
        self.client_buffer = b''

        # sshd sees this local port as its peer port.  cekssh uses it to
        # match the session back to the real client IP.
        if self.target_port:
            try:
                local_port = self.target.getsockname()[1]
                record_map(local_port, self.real_ip)
            except Exception as exc:
                print('map error: ' + str(exc))

        self.server.printLog(self.log)
        self.doCONNECT()

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            (recv, _, err) = select.select(socs, [], socs, 3)
            if err:
                error = True
            if recv:
                for in_ in recv:
                    try:
                        data = in_.recv(BUFLEN)
                        if data:
                            if in_ is self.target:
                                self.client.sendall(data)
                            else:
                                while data:
                                    sent = self.target.send(data)
                                    if sent <= 0:
                                        error = True
                                        break
                                    data = data[sent:]
                            count = 0
                        else:
                            error = True
                            break
                    except:
                        error = True
                        break
            if count == TIMEOUT:
                error = True
            if error:
                break


def print_usage():
    print('Usage: proxy.py -p <port>')
    print('       proxy.py -b <bindAddr> -p <port>')
    print('       proxy.py -b 0.0.0.0 -p 80')


def parse_args(argv):
    global LISTENING_ADDR
    global LISTENING_PORT

    try:
        opts, args = getopt.getopt(argv, "hb:p:", ["bind=", "port="])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print_usage()
            sys.exit()
        elif opt in ("-b", "--bind"):
            LISTENING_ADDR = arg
        elif opt in ("-p", "--port"):
            LISTENING_PORT = int(arg)


def main(host=None, port=None):
    if host is None:
        host = LISTENING_ADDR
    if port is None:
        port = LISTENING_PORT
    try:
        os.makedirs(os.path.dirname(MAP_FILE), exist_ok=True)
        prune_map(int(time.time()))
    except Exception:
        pass
    print("\n:-------PythonProxy-------:\n")
    print("Listening addr: " + LISTENING_ADDR)
    print("Listening port: " + str(LISTENING_PORT) + "\n")
    print("Target: " + DEFAULT_HOST)
    print(":-------------------------:\n")
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print('Stopping...')
            server.close()
            break


if __name__ == '__main__':
    parse_args(sys.argv[1:])
    main(LISTENING_ADDR, LISTENING_PORT)
