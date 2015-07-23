from twisted.web import proxy, http
from twisted.internet import reactor
from twisted.python import log

import urlparse, base64
from twisted.web.http import HTTPClient, Request, HTTPChannel
from twisted.internet.protocol import ClientFactory

import sys
log.startLogging(sys.stdout)


class MyProxyClient(HTTPClient):
    """
    Used by ProxyClientFactory to implement a simple web proxy.

    @ivar _finished: A flag which indicates whether or not the original request
        has been finished yet.
    """
    _finished = False

    def __init__(self, method, uri, version, headers, data, father):
        self.father = father
        self.method = method
        self.uri = uri
        self.headers = headers
        self.data = data

    def connectionMade(self):
        self.sendCommand(self.method, self.uri)
        for header, value in self.headers.items():
            self.sendHeader(header, value)
        self.endHeaders()
        self.transport.write(self.data)

    def handleStatus(self, version, code, message):
        self.father.setResponseCode(int(code), message)

    def handleHeader(self, key, value):
        # t.web.server.Request sets default values for these headers in its
        # 'process' method. When these headers are received from the remote
        # server, they ought to override the defaults, rather than append to
        # them.
        if key.lower() in ['server', 'date', 'content-type']:
            self.father.responseHeaders.setRawHeaders(key, [value])
        else:
            self.father.responseHeaders.addRawHeader(key, value)

    def handleResponsePart(self, buffer):
        self.father.write(buffer)

    def handleResponseEnd(self):
        """
        Finish the original request, indicating that the response has been
        completely written to it, and disconnect the outgoing transport.
        """
        if not self._finished:
            self._finished = True
            self.father.finish()
            self.transport.loseConnection()



class MyProxyClientFactory(ClientFactory):
    """
    Used by ProxyRequest to implement a simple web proxy.
    """
    protocol = MyProxyClient

    def __init__(self, method, uri, version, headers, data, father):
        self.father = father
        self.method = method
        self.uri = uri
        self.headers = headers
        self.data = data
        self.version = version

    def buildProtocol(self, addr):
        return self.protocol(self.method, self.uri, self.version,
                             self.headers, self.data, self.father)

    def clientConnectionFailed(self, connector, reason):
        """
        Report a connection failure in a response to the incoming request as
        an error.
        """
        self.father.setResponseCode(501, 'Gateway error')
        self.father.responseHeaders.addRawHeader('Content-Type', 'text/html')
        self.father.write('<h1>Could not connect</h1>')
        self.father.finish()



class MyProxyRequest(Request):
    def __init__(self, channel, queued, reactor=reactor):
        Request.__init__(self, channel, queued)
        self.reactor = reactor

    def process(self):
        headers = self.getAllHeaders().copy()

        try:
            upstreamProxy = headers.pop('x-upstream-proxy')
        except KeyError:
            self.setResponseCode(501, 'Gateway error')
            self.responseHeaders.addRawHeader('Content-Type', 'text/html')
            self.write('<h1>Missing X-Upstream-Proxy header</h1>')
            self.finish()
            return

        if '@' in upstreamProxy:
            upstreamProxyAuth, upstreamProxyHost = upstreamProxy.split('@', 1)
        else:
            upstreamProxyHost = upstreamProxy
            upstreamProxyAuth = None

        if ':' in upstreamProxyHost:
            upstreamProxyHost, upstreamProxyPort = upstreamProxyHost.split(':', 1)
            upstreamProxyPort = int(upstreamProxyPort)
        else:
            upstreamProxyPort = 8080

        headers['proxy-connection'] = 'close'
        if upstreamProxyAuth:
            headers['proxy-authorization'] = 'Basic ' + base64.b64encode(upstreamProxyAuth)

        self.content.seek(0, 0)
        data = self.content.read()

        clientFactory = MyProxyClientFactory(self.method, self.uri, self.clientproto, headers, data, self)
        self.reactor.connectTCP(upstreamProxyHost, upstreamProxyPort, clientFactory)


class MyProxy(HTTPChannel):
    requestFactory = MyProxyRequest


class MyProxyFactory(http.HTTPFactory):
    protocol = MyProxy


# TODO: unite with https://github.com/fmoo/twisted-connect-proxy/blob/master/server.py
# to support https

# tmp: https://github.com/abhinavsingh/proxy.py/blob/develop/proxy.py

reactor.listenTCP(8080, MyProxyFactory())
#endpoints.serverFromString(reactor, 'tcp:8080').listen(ProxyFactory())
reactor.run()
