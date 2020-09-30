from scapy.all import *
import time

# time period for trigger a poll event (ms)
POLLING_PERIOD:float = 0.05
LOCAL_IPADDR:str = "10.0.1.1"
CTRL_PROTO:int = 0x9F
POLL_RETRIAL_MAXNUM:int = 10

FETCH_SUCCESS = False
Timestamp:int = 0

# Control packet format
# https://scapy.readthedocs.io/en/latest/build_dissect.html
class Control_t(Packet):
    name = "Control_t "
    fields_desc = [
        ShortField("qid", 0),
        XByteField("monNum", 0),
        XByteField("time", 0),
        XByteField("count", 0)
    ]

def collector(packet):
    if IP in packet:
        if packet[IP].proto == CTRL_PROTO:
            # check if with corrrect timestamp
            if bytes(packet[IP].payload)[3] == Timestamp:
                FETCH_SUCCESS = True
                print("Polled %d" % (bytes(packet[IP].payload)[4]))

# can improve with rev-aggr maybe
def mpoll(destMAC:list, destIP:list, qid:int, timestamp:int):
    FETCH_SUCCESS = False
    if len(destMAC) != len(destIP) {
        return
    }
    # mcast to monitors
    ctrl_payload = Control_t(qid=qid, monNum=len(destIP), time=timestamp)
    poll_pkt = Ether()/IP(src=LOCAL_IPADDR, proto=CTRL_PROTO)/ctrl_payload

    for mon_idx in range(len(destIP)):
        poll_pkt[Ether].dst = destMAC[mon_idx]
        poll_pkt[IP].dst = destIP[mon_idx]
        sendp(poll_pkt)

    # sniff for packets
    sniff(iface="any", prn=collector, timeout=POLLING_PERIOD)


if __name__ == "__main__":
    # TODO: add a while loop here (escape condition required though)

    # inactive phase
    time.sleep(POLLING_PERIOD)
    # active phase
    retrial_times:int = 0
    while (not FETCH_SUCCESS) and (retrial_times < POLL_RETRIAL_MAXNUM):
        Timestamp += 1
        retrial_times += 1
        mpoll(destMAC=["08:00:00:00:05:00", "08:00:00:00:06:00"], destIP=["10.2.11.5", "10.2.11.6"], qid=1, timestamp=Timestamp)

    if retrial_times >= POLL_RETRIAL_MAXNUM:
        print("Retransmittion failed after %d retrial" % (retrial_times))
