import os
import logging

from twisted.internet import reactor
from twisted.web import http

from StrippingProxy import StrippingProxy


class Setting:
    def __init__(self):
        pass

    @staticmethod
    def __exec_shell(command):
        return os.popen(command).read()

    def enable_ip_forwarding(self):
        self.__exec_shell('echo "1" > /proc/sys/net/ipv4/ip_forward')

    def disable_ip_forwarding(self):
        self.__exec_shell('echo "0" > /proc/sys/net/ipv4/ip_forward')


def main():
    if 0 == os.getuid():
        pass
    else:
        print("We need root permission")
        exit()

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
