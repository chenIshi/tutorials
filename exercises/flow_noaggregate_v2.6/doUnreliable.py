#!/usr/bin/env python2
from scapy.all import *
import time
import struct

# time period for trigger a poll event (ms)
POLLING_PERIOD = 0.05
LOCAL_IPADDR = "10.0.1.1"
CTRL_PROTO = 0x9F
POLL_RETRIAL_MAXNUM = 6
POLLING_NUMBER = 1000

FETCH_SUCCESS = False
Timestamp = 0
failcount = 0

# Control packet format
# https://scapy.readthedocs.io/en/latest/build_dissect.html
class Control_t(Packet):
    name = "Control_t "
    fields_desc = [
        ShortField("qid", 0),
        ShortField("count", 0),
        ShortField("timestamp", 0)
    ]

# can improve with rev-aggr maybe
def mpoll(destMAC, destIP, qid, timestamp):
    global FETCH_SUCCESS
    global Timestamp

    local_aggr_count = 0

    FETCH_SUCCESS = False
    if len(destMAC) != len(destIP):
        return
    
    # mcast to monitors
    ctrl_payload = Control_t(qid=qid, timestamp=Timestamp)
    poll_pkt = Ether()/IP(src=LOCAL_IPADDR, proto=CTRL_PROTO)/ctrl_payload

    for mon_idx in range(len(destIP)):
        poll_pkt[Ether].dst = destMAC[mon_idx]
        poll_pkt[IP].dst = destIP[mon_idx]
        reply = srp1(poll_pkt, timeout=POLLING_PERIOD, verbose=0)
        if not (reply is None):
            if IP in reply:
                if reply[IP].proto == CTRL_PROTO:
                    fetched_timestamp = struct.unpack('>H', bytes(reply[IP].payload)[4:6])
                    if fetched_timestamp[0] == Timestamp:
                        local_aggr_count += 1
                        if local_aggr_count >= len(destIP):
                            FETCH_SUCCESS = True

                    else:
                        print("Get Wrong Timestamp %d instead of %d" % (fetched_timestamp[0], Timestamp))
                else:
                    print("Not a control pkt")
            else:
                print("Not a IP pkt")

if __name__ == "__main__":
    # TODO: add a while loop here (escape condition required though)
    for repoll in range(POLLING_NUMBER):
        # inactive phase
        time.sleep(POLLING_PERIOD)
        # active phase
        retrial_times = 0
        Timestamp += 1
        mpoll(destMAC=["08:00:00:00:02:22", "08:00:00:00:03:33"], destIP=["10.1.2.2", "10.1.3.3"], qid=1, timestamp=Timestamp)

        if not FETCH_SUCCESS:
            failcount += 1

        FETCH_SUCCESS = False

    print("Failed count = %d" % (failcount))