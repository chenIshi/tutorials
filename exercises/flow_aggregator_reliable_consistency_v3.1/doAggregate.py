#!/usr/bin/env python2
from scapy.all import *
import time
import struct
import datetime

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

diff_counts = []
last_timestampA = 0
last_timestampB = 0

polling_time = 0

# Control packet format
# https://scapy.readthedocs.io/en/latest/build_dissect.html
class Control_t(Packet):
    name = "Control_t "
    fields_desc = [
        ShortField("qid", 0),
        BitField("flagOverflow", 0, 1),
        BitField("flagCleanup", 0, 1),
        BitField("count", 0, 22),
        ShortField("seq", 0),
        BitField("timestampA", 0, 32),
        BitField("timestampB", 0, 32)
]

# can improve with rev-aggr maybe
def mpoll(destMAC, destIP, qid, timestamp, repollNumber):
    global FETCH_SUCCESS
    global Timestamp
    global isCleanup
    global diff_counts, last_timestampA, last_timestampB

    FETCH_SUCCESS = False
    if len(destMAC) != len(destIP):
        return

    # mcast to monitors
    ctrl_payload = Control_t(qid=qid, seq=Timestamp)

    '''
    if isCleanup or repollNumber % RST_COUNTER_PERIOD == 0:
        # by default, if no response if recved, then it will be a cleanup next round
        isCleanup = True
        ctrl_payload.flagCleanup = 1
    '''
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
                        unpure_flags = struct.unpack('>B', bytes(reply[IP].payload)[2:3])
                        overflow_flags = (unpure_flags[0] & 0b10000000) >> 7
                        cleanup_flags = (unpure_flags[0] & 0b01000000) >> 6
                        timestampA = struct.unpack('>L', bytes(reply[IP].payload)[7:11])[0]
                        timestampB = struct.unpack('>L', bytes(reply[IP].payload)[11:15])[0]
                        if last_timestampA != 0 and last_timestampB != 0 and timestampA != 0 and timestampB != 0:
                            diff_counts.append(timestampA - last_timestampA + timestampB - last_timestampB)
                        last_timestampA = timestampA
                        last_timestampB = timestampB
                        if overflow_flags == 1:
                            print("Overflowed!")
                        # print("Polled %d" % (fetched_timestamp[0]))
                    else:
                        print("Get Wrong Seq %d instead of %d" % (fetched_timestamp[0], Timestamp))
                else:
                    print("Not a control pkt")
            else:
                print("Not a IP pkt")

if __name__ == "__main__":
    # TODO: add a while loop here (escape condition required though)
    for repoll in range(POLLING_NUMBER):
        # inactive phase
        time.sleep(POLLING_PERIOD - polling_time)
        start_time = datetime.datetime.now()
        # active phase
        retrial_times = 0
        while (not FETCH_SUCCESS) and (retrial_times < POLL_RETRIAL_MAXNUM):
            Timestamp += 1
            retrial_times += 1
            mpoll(destMAC=["08:00:00:00:04:44"], destIP=["10.1.4.4"], qid=1, timestamp=Timestamp, repollNumber=repoll)

        if (not FETCH_SUCCESS) and (retrial_times >= POLL_RETRIAL_MAXNUM):
            if isCleanup:
                print("Retransmittion failed during cleanup in time %d" % (repoll))
            else:
                print("Retransmittion failed in time %d" % (repoll))
            break
        elif FETCH_SUCCESS:
            end_time = datetime.datetime.now()
            time_diff = end_time - start_time
            polling_time = time_diff.total_seconds()
            if polling_time > POLLING_PERIOD:
                polling_time = POLLING_PERIOD

        FETCH_SUCCESS = False

    if sum(diff_counts) != 0 and len(diff_counts) > 0:
        avg = sum(diff_counts) / float(len(diff_counts))
        var = (sum((xi - avg) ** 2 for xi in diff_counts) / float(len(diff_counts))) ** 0.5

        print("Avg Count = ", avg)
        print("Var Count = ", var)
    elif len(diff_counts) <= 0:
        print("diff count len <= 0!")
    elif sum(diff_counts) == 0:
        print("diff count sum = 0!")
