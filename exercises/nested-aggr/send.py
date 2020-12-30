#!/usr/bin/env python2
from scapy.all import *
import time
import struct

TYPE_MYFORWARD = 0x1234

class MyForward_t(Packet):
    name = "MyForward_t "
    fields_desc = [
        ShortField("srcID", 0),
        ShortField("dstID", 0)
]

if __name__ == "__main__":
    pkt = Ether(type=TYPE_MYFORWARD)/MyForward_t(srcID=0, dstID=1)
    reply = srp1(pkt)
    if Ether in reply:
        print("Hi")
