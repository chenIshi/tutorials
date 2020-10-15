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
RST_COUNTER_PERIOD = 10

# MONITOR_NUMs_PER_QUERY = 2
FETCH_SUCCESS = False
Timestamp = 0
isCleanup = False
failcount = 0
errorcount = 0

# Control packet format
# https://scapy.readthedocs.io/en/latest/build_dissect.html
class Control_t(Packet):
    name = "Control_t "
    fields_desc = [
        ShortField("qid", 0),
        BitField("flagOverflow", 0, 1),
        BitField("flagCleanup", 0, 1),
        BitField("count", 0, 22),
        ShortField("timestamp", 0),
        ShortField("responseID", 0),
        ShortField("monitorBitmap", 0)
]

# can improve with rev-aggr maybe
def mpoll(destMAC, destIP, qid, timestamp, repollNumber):
    global FETCH_SUCCESS
    global Timestamp
    global isCleanup
    global errorcount

    FETCH_SUCCESS = False
    if len(destMAC) != len(destIP):
        return
    
    # mcast to monitors
    ctrl_payload = Control_t(qid=qid, timestamp=Timestamp)

    if isCleanup or repollNumber % RST_COUNTER_PERIOD == 0:
        # by default, if no response if recved, then it will be a cleanup next round
        isCleanup = True
        ctrl_payload.flagCleanup = 1

    # Tweak this according to the number of your numbers
    ctrl_payload.monitorBitmap = 0xFFFC

    poll_pkt = Ether()/IP(src=LOCAL_IPADDR, proto=CTRL_PROTO)/ctrl_payload

    for mon_idx in range(len(destIP)):
        poll_pkt[Ether].dst = destMAC[mon_idx]
        poll_pkt[IP].dst = destIP[mon_idx]
        
        reply = srp1(poll_pkt, timeout=POLLING_PERIOD, verbose=0)
        if not (reply is None):
            if IP in reply:
                if reply[IP].proto == CTRL_PROTO:
                    fetched_timestamp = struct.unpack('>H', bytes(reply[IP].payload)[5:7])
                    if fetched_timestamp[0] == Timestamp:
                        FETCH_SUCCESS = True
                        isCleanup = False
                        response_id = struct.unpack('>H', bytes(reply[IP].payload)[7:9])
                        monitor_bitmap = struct.unpack('>H', bytes(reply[IP].payload)[9:11])
                        if monitor_bitmap != 0xFFFF:
                            errorcount += 1
                        
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
        Timestamp += 1
        mpoll(destMAC=["08:00:00:00:04:44"], destIP=["10.1.4.4"], qid=1, timestamp=Timestamp, repollNumber=repoll)
        '''
        while (not FETCH_SUCCESS) and (retrial_times < POLL_RETRIAL_MAXNUM):
            Timestamp += 1
            retrial_times += 1
            mpoll(destMAC=["08:00:00:00:04:44"], destIP=["10.1.4.4"], qid=1, timestamp=Timestamp, repollNumber=repoll)
        '''
        if not FETCH_SUCCESS:
            failcount += 1

        FETCH_SUCCESS = False
