#!/usr/bin/env python2
from scapy.all import *
import time
import struct

SIGNAL_TIMEOUT = 10
CTRL_SIGNAL = 0x9D
SEND_PERIOD = 0.02
SEND_NUMBER = 1000
TARGET_IP = "10.0.3.3"
TARGET_MAC = "08:00:00:00:03:00"

class Signal_t(Packet):
    name = "Signal_t "
    fields_desc = [     
        XByteField("synack", 0)
]

if __name__ == "__main__":
    start_sending = False
    pkts = sniff(count=1, filter="host 10.0.1.1", timeout=SIGNAL_TIMEOUT)
    for pkt in pkts:
        if IP in pkt:
            if pkt[IP].proto == CTRL_SIGNAL:
                start_sending = True

    if not start_sending:
        print("No starting signal back")
        exit(1)

    for resend_number in range(SEND_NUMBER):
        time.sleep(SEND_PERIOD)
        send_pkt = Ether(dst=TARGET_MAC)/IP(dst=TARGET_IP)/TCP()
        sendp(send_pkt)
    
