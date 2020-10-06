'''
Analyze the flow pass through switches
Interested fields included:
- Throughput
- Goodput ?
- PPS (Packet Per Second) ?
'''

from scapy.all import *
import os
import json

InterfaceNames = []
Throughtputs = []
PacketCounts = []

PPS = []

packet_count = 0
throughtput = 0

currentTime = 0
accumulatedPPS = 0

def doStatistic(packet):
    global packet_count, throughtput
    global currentTime, accumulatedPPS, PPS

    packet_count += 1
    throughtput += len(packet)

    # PPS staticists
    # init current time
    if currentTime == 0:
        currentTime = packet.time

    # accmulate count within one sec
    if packet.time > currentTime + 1:
        PPS.append(str(accumulatedPPS))
        accumulatedPPS = 0
        currentTime = packet.time

    accumulatedPPS += 1



if __name__ = "__main__":
    for filename in os.listdir('pcaps/'):
        if filename.endswith(".pcap"):
            InterfaceNames.append(filename[:-5])
            
            packet_count = 0
            throughtput = 0

            sniff(offline=filename, prn=doStatistic, store=0)

            PacketCounts.append(packet_count)
            Throughtputs.append(throughtput)

            dst = "logs/" + filename[:-5] +".json"
            with open(dst, "w") as f:
                json.dump(PPS, f)

            PPS = []

        
