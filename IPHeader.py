from socket import gethostname, gethostbyname, inet_aton
from struct import pack
from typing_extensions import Self

"""
Author: revi1337
Date : 2022-10-31
"""

class IP(object):

    def __init__(self):
        """
        Set Default IP Segments (20 Bytes)
        (1) Version : IPv4(defualt), IPv6

        (2) IP Header Length(ihl) : Shift left to 4bit and `or` with preihl
                0100 0000 (IPv4)
                0000 0101 (preihl : 5 word is common)
                ---------
                0100 0101

        (3) Protocol : ICMP, TCP, UDP, etc..

        (4) totalLength : IP Header(20 Bytes) + TCP Header(20 Bytes)

        (5) Soucre and Destination Address : Your Private Address
        """

        self.version = 0x4
        self.preihl = 0x5
        self.ihl = (self.version << 4) + self.preihl

        self.tos = 0x0
        self.totalLength = 0x28
        self.identification = 0xabcd

        self.flag = 0x0
        self.fragmentOffset = 0x0
        self.flagAndFragmentOffset = (self.flag << 13) + self.fragmentOffset
        
        self.ttl = 0x40
        self.protocol = 0x1
        self.headerChecksum = 0x0
        self.sourceAddress = inet_aton(gethostbyname(gethostname()))
        self.destinationAddress = inet_aton(gethostbyname(gethostname()))
        
    def setProtocol(self, protocol: str) -> Self:
        """
        Set Serveral Protocol 
        """

        if protocol.lower() not in ["icmp", "igmp", "tcp", "igrp", "udp", "gre", "esp", "ah", "skip", "eigrp", "ospf", "l2tp"]:
            raise(ValueError("Specify Correct Protocol"))
        
        protocol = protocol.lower()

        if protocol == "icmp": protocol = 0x1
        elif protocol == "igmp": protocol = 0x2
        elif protocol == "tcp": protocol = 0x6
        elif protocol == "igrp": protocol = 0x9
        elif protocol == "udp": protocol = 0x11
        elif protocol == "gre": protocol = 0x2f
        elif protocol == "esp": protocol = 0x32
        elif protocol == "ah": protocol = 0x33
        elif protocol == "skip": protocol = 0x39
        elif protocol == "eigrp": protocol = 0x58
        elif protocol == "ospf": protocol = 0x59
        elif protocol == "l2tp": protocol = 0x73

        self.protocol = protocol
        
        return self

    def generateTcpHeader(self):
        """
        Convert to Byte Object
        (1) Byte Order : Big Endian
        (2) ! : Network Format
            B : unsigned int (1 Byte)
            H : unsigned int (4 Byte)      
            s : String
        """
        return pack('!BBHHHBBH4s4s',
            self.ihl, self.tos, self.totalLength, self.identification,
            self.flagAndFragmentOffset, self.ttl, self.protocol,
            self.headerChecksum, self.sourceAddress, self.destinationAddress
        )

if __name__ == "__main__":
    pck1 = IP()
    print(pck1.setProtocol("udp").generateTcpHeader())
    pck2 = IP()
    print(pck2.setProtocol("tcp").generateTcpHeader())
    
    
