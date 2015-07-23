"""
Bastion proxy to connect to other proxies via it.

Based on https://raw.githubusercontent.com/fmoo/twisted-connect-proxy/master/server.py

Thanks to Peter Ruibal for Twisted HTTPS proxy support.
"""
from __future__ import division, absolute_import
__version__ = '1.1.0'

import base64

from twisted.internet.protocol import ClientFactory
from twisted.web.proxy import Proxy, ProxyRequest, HTTPClient
from twisted.python import log


class ConnectProxyRequest(ProxyRequest):
    def process(self):
        headers = self.getAllHeaders().copy()

        try:
            auth_string = headers.pop('proxy-authorization')
        except KeyError:
            return self.fail('Invalid request', 'Missing Proxy-Authorization header', status=400)

        auth_method, upstream_proxy = auth_string.split(' ', 1)
        if auth_method.lower() != 'basic':
            return self.fail('Invalid request', 'Invalid auth method', status=400)

        upstream_proxy = base64.b64decode(upstream_proxy)
        upstream_proxy_host, upstream_proxy_port, upstream_proxy_auth = upstream_proxy.split(',')
        upstream_proxy_port = int(upstream_proxy_port)
        headers['proxy-authorization'] = 'Basic ' + base64.b64encode(upstream_proxy_auth)

        client_factory = ConnectProxyClientFactory(self.method, self.uri, headers, self)
        self.reactor.connectTCP(upstream_proxy_host, upstream_proxy_port, client_factory)

    def fail(self, message, body, status=501):
        self.setResponseCode(status, message)
        self.responseHeaders.addRawHeader('Content-Type', 'text/html')
        self.write(body)
        self.finish()


class ConnectProxy(Proxy):
    requestFactory = ConnectProxyRequest
    connectedRemote = None

    def requestDone(self, request):
        if self.connectedRemote is not None:
            self.connectedRemote.connectedClient = self
        else:
            Proxy.requestDone(self, request)

    def connectionLost(self, reason):
        if self.connectedRemote is not None:
            self.connectedRemote.transport.loseConnection()
        Proxy.connectionLost(self, reason)

    def dataReceived(self, data):
        if self.connectedRemote is None:
            Proxy.dataReceived(self, data)
        else:
            # Once proxy is connected, forward all bytes received
            # from the original client to the remote server.
            self.connectedRemote.transport.write(data)


class ConnectProxyClient(HTTPClient):
    connectedClient = None

    def __init__(self, method, uri, headers):
        self.method = method
        self.uri = uri
        self.headers = headers

    def connectionMade(self):
        self.factory.request.channel.connectedRemote = self
        self.sendCommand(self.method, self.uri)
        for header, value in self.headers.items():
            self.sendHeader(header, value)
        self.endHeaders()
        self.factory.request.startedWriting = True
        self.factory.request.finish()

    def connectionLost(self, reason):
        if self.connectedClient is not None:
            self.connectedClient.transport.loseConnection()

    def dataReceived(self, data):
        if self.connectedClient is not None:
            # Forward all bytes from the remote server back to the
            # original connected client
            self.connectedClient.transport.write(data)
        else:
            log.msg('UNEXPECTED DATA RECEIVED:', data)


class ConnectProxyClientFactory(ClientFactory):
    protocol = ConnectProxyClient
    noisy = False

    def __init__(self, method, uri, headers, request):
        self.request = request
        self.method = method
        self.uri = uri
        self.headers = headers

    def clientConnectionFailed(self, connector, reason):
        self.request.fail('Gateway Error', str(reason))

    def buildProtocol(self, addr):
        p = self.protocol(self.method, self.uri, self.headers)
        p.factory = self
        return p


def main():
    import argparse
    ap = argparse.ArgumentParser(prog='bastion-proxy',
                                 description="Bastion proxy to connect to other proxies via it.",
                                 version=__version__,
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument('--port', default=8080, type=int, help='listen port')
    ap.add_argument('--syslog', action='store_true', help='log to syslog instead of stderr')
    ap.add_argument('--syslog-address', help='syslog socket address')
    args = ap.parse_args()

    import logging
    import logging.handlers
    if args.syslog:
        if args.syslog_address:
            log_handler = logging.handlers.SysLogHandler(address=args.syslog_address)
        else:
            log_handler = logging.handlers.SysLogHandler()
        log_formatter = None
    else:
        log_handler = logging.StreamHandler()
        log_formatter = logging.Formatter('%(asctime)s %(levelname)s  %(message)s')
    log_handler.setFormatter(log_formatter)
    logging.root.addHandler(log_handler)
    logging.root.setLevel(logging.NOTSET)
    observer = log.PythonLoggingObserver(loggerName='bastion')
    observer.start()

    import twisted.web.http
    factory = twisted.web.http.HTTPFactory()
    factory.protocol = ConnectProxy
    factory.noisy = False
    twisted.internet.reactor.listenTCP(args.port, factory)
    twisted.internet.reactor.run()


if __name__ == '__main__':
    main()
