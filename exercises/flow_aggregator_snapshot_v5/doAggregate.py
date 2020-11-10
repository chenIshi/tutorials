#!/usr/bin/env python2
from scapy.all import *
import time
import struct
import datetime

# time period for trigger a poll event (ms)
POLLING_PERIOD = 0.2
INSTALL_WAIT = 0.1
LOCAL_IPADDR = "10.0.1.1"
CTRL_PROTO = 0x9F
CTRL_SNAPSHOT = 0x9E
POLL_RETRIAL_MAXNUM = 6
POLLING_NUMBER = 100
RST_COUNTER_PERIOD = 10
# EXPECT_DIFF_COUNT = 50

# MONITOR_NUMs_PER_QUERY = 2
FETCH_SUCCESS = False
Timestamp = 0
isCleanup = False

isPoll = False
isSnapshotToPoll = False

diff_timestamp = []
prev_timestamp = 0

polling_time = 0
installing_time = 0;
start_time = None

# Control packet format
# https://scapy.readthedocs.io/en/latest/build_dissect.html
class Control_t(Packet):
    name = "Control_t "
    fields_desc = [
        ShortField("qid", 0),
        BitField("flagOverflow", 0, 1),
        BitField("flagCleanup", 0, 1),
        BitField("count", 0, 22),
        ShortField("timestamp", 0)
]

class Snapshot_t(Packet):
    name = "Snapshot_t "
    fields_desc = [
        ShortField("qid", 0),
        BitField("timestamp", 0, 32),
        ShortField("seq", 0)
]

# can improve with rev-aggr maybe
def mpoll(destMAC, destIP, qid, timestamp, repollNumber):
    global FETCH_SUCCESS, INSTALL_WAIT
    global Timestamp
    global isCleanup, isPoll
    global isSnapshotToPoll
    global diff_timestamp, prev_timestamp
    global installing_time, start_time

    FETCH_SUCCESS = False
    if len(destMAC) != len(destIP):
        return

    # wait until the snapshot is taken
    if isSnapshotToPoll:
        time.sleep(INSTALL_WAIT - installing_time)
        isSnapshotToPoll = False

    # mcast to monitors
    ctrl_payload = Control_t(qid=qid, timestamp=Timestamp)
    snapshot_payload = Snapshot_t(qid=qid, timestamp=100000,seq=Timestamp)

    '''
    if isCleanup or repollNumber % RST_COUNTER_PERIOD == 0:
        # by default, if no response if recved, then it will be a cleanup next round
        isCleanup = True
        ctrl_payload.flagCleanup = 1
    '''
    if isPoll:
        poll_pkt = Ether()/IP(src=LOCAL_IPADDR, proto=CTRL_PROTO)/ctrl_payload
    else:
        poll_pkt = Ether()/IP(src=LOCAL_IPADDR, proto=CTRL_SNAPSHOT)/snapshot_payload

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
                        isPoll = False
                        unpure_flags = struct.unpack('>B', bytes(reply[IP].payload)[2:3])
                        overflow_flags = (unpure_flags[0] & 0b10000000) >> 7
                        cleanup_flags = (unpure_flags[0] & 0b01000000) >> 6
                        '''
                        count = struct.unpack('>L', bytes(reply[IP].payload)[1:5])[0] & 0x003FFFFF
                        if prev_count != 0:
                            diff_counts.append(count - prev_count)
                        prev_count = count
                        '''
                        if overflow_flags == 1:
                            print("Overflowed!")
                        # print("Polled %d" % (fetched_timestamp[0]))
                    else:
                        print("Get Wrong Timestamp %d instead of %d" % (fetched_timestamp[0], Timestamp))
                elif reply[IP].proto == CTRL_SNAPSHOT:
                    fetched_seq = struct.unpack('>H', bytes(reply[IP].payload)[6:8])
                    if fetched_seq[0] == Timestamp:
                        isPoll = True
                        isSnapshotToPoll = True
                        timestamp = struct.unpack('>L', bytes(reply[IP].payload)[2:6])[0]
                        if prev_timestamp != 0 and timestamp > prev_timestamp:
                            diff_timestamp.append(timestamp - prev_timestamp)
                        prev_timestamp = timestamp
                        if not (start_time is None):
                            end_time = datetime.datetime.now()
                            installing_time = (end_time - start_time).total_seconds()
                            if installing_time >INSTALL_WAIT:
                                print("Warning: installing timeout: ", installing_time)
                                installing_time = INSTALL_WAIT
                else:
                    print("Not a control pkt")
            else:
                print("Not a IP pkt")

if __name__ == "__main__":
    # TODO: add a while loop here (escape condition required though)
    for repoll in range(POLLING_NUMBER):
        # inactive phase
        time.sleep(POLLING_PERIOD)
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
                print("Warning: polling timeout: ", polling_time, "repoll = ", repoll)
                polling_time = POLLING_PERIOD

        FETCH_SUCCESS = False

    avg = sum(diff_timestamp) / float(len(diff_timestamp))
    var = (sum((xi - avg) ** 2 for xi in diff_timestamp) / float(len(diff_timestamp))) ** 0.5

    print("Avg Timestamp = ", avg)
    print("Var Timestamp = ", var)
