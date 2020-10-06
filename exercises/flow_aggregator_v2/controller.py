#!/usr/bin/env python2
from scapy.all import *
import time
import struct

# time period for trigger a poll event (ms)
POLLING_PERIOD = 0.05
LOCAL_IPADDR = "10.0.1.1"
CTRL_PROTO = 0x9F
POLL_RETRIAL_MAXNUM = 10

FETCH_SUCCESS = False
Timestamp = 0

# Control packet format
# https://scapy.readthedocs.io/en/latest/build_dissect.html
class Control_t(Packet):
    name = "Control_t "
    fields_desc = [
        ShortField("qid", 0),
        XByteField("monNum", 0),
        ShortField("count", 0),
        ShortField("timestamp", 0)
    ]

def collector(packet):
    global FETCH_SUCCESS
    print("Hello in collector")
    if IP in packet:
        if packet[IP].proto == CTRL_PROTO:
            # check if with corrrect timestamp
            if bytes(packet[IP].payload)[3] == Timestamp:
                FETCH_SUCCESS = True
                print("Polled %d" % (bytes(packet[IP].payload)[4]))
            else:
                print("Get Wrong timestamp %d not %d" % (bytes(packet[IP].payload)[4], Timestamp))

# can improve with rev-aggr maybe
def mpoll(destMAC, destIP, qid, timestamp):
    global FETCH_SUCCESS

    FETCH_SUCCESS = False
    if len(destMAC) != len(destIP):
        return
    
    # mcast to monitors
    ctrl_payload = Control_t(qid=qid, monNum=len(destIP), timestamp=Timestamp)
    poll_pkt = Ether()/IP(src=LOCAL_IPADDR, proto=CTRL_PROTO)/ctrl_payload

    for mon_idx in range(len(destIP)):
        poll_pkt[Ether].dst = destMAC[mon_idx]
        poll_pkt[IP].dst = destIP[mon_idx]
	# poll_pkt.show()
	if mon_idx == (len(destIP) - 1):
            reply = srp1(poll_pkt, timeout=POLLING_PERIOD)
            if not (reply is None):
                if IP in reply:
                    if reply[IP].proto == CTRL_PROTO:
                        fetched_timestamp = struct.unpack('>H', bytes(reply[IP].payload)[5:7])
                        if fetched_timestamp[0] == Timestamp:
                            FETCH_SUCCESS = True
                            print("Polled %d" % (fetched_timestamp[0]))
                        else:
                            print("Get Wrong Timestamp %d instead of %d" % (fetched_timestamp[0], Timestamp))
                    else:
                        print("Not a control pkt")
                else:
                    print("Not a IP pkt")
	else:
            sendp(poll_pkt)
        # sendp(poll_pkt)

    # sniff for packets
    # sniff(prn=collector, timeout=POLLING_PERIOD)
    # print("Hello after sniff")

if __name__ == "__main__":
    # TODO: add a while loop here (escape condition required though)

    # inactive phase
    time.sleep(POLLING_PERIOD)
    # active phase
    retrial_times = 0
    while (not FETCH_SUCCESS) and (retrial_times < POLL_RETRIAL_MAXNUM):
        Timestamp += 1
	# Timestamp = 1
        retrial_times += 1
        mpoll(destMAC=["08:00:00:00:02:22", "08:00:00:00:03:33"], destIP=["10.1.2.2", "10.1.3.3"], qid=1, timestamp=Timestamp)

    if (not FETCH_SUCCESS) and (retrial_times >= POLL_RETRIAL_MAXNUM):
        print("Retransmittion failed after %d retrial" % (retrial_times))
