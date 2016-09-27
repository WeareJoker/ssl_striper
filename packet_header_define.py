from struct import pack

ZERO_MASK = pack('!6B', *(0x00,) * 6)
BROADCAST_MASK = pack('!6B', *(0xFF,) * 6)
ARP_REQUEST_OP = pack('!H', 0x0001)
ARP_REPLY_OP = pack('!H', 0x0002)
ARP_TYPE_ETHERNET_PROTOCOL = pack('!H', 0x0806)
ARP_PROTOCOL_TYPE = pack('!HHBB', 0x0001, 0x0800, 0x0006, 0x0004)
