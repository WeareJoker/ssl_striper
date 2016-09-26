import logging

from twisted.internet import reactor
from twisted.web import http

from StrippingProxy import StrippingProxy


def main():
    # Using Twisted
    logging.basicConfig(level=logging.WARNING, format='%(asctime)s %(message)s',
                        filename='sslstrip.log', filemode='w')

    strippingFactory = http.HTTPFactory(timeout=10)
    strippingFactory.protocol = StrippingProxy

    reactor.listenTCP(int(10000), strippingFactory)

    print("Running")

    reactor.run()


if __name__ == '__main__':
    main()
