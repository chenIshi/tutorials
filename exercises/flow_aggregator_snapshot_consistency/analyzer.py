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
    # filter out those stupid ICMP protocol unreachiable
    if IP in packet:
        if packet[IP].proto == 1:
            return

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



if __name__ == "__main__":
    for filename in os.listdir('pcaps/'):
        if filename.endswith(".pcap"):
            # InterfaceNames.append(filename[:-5])
            
            packet_count = 0
            throughtput = 0
                        
            location = "pcaps/" + filename
            # print(location)
            file_has_content = True

            try:
                sniff(offline=location, prn=doStatistic, store=False)
            except:
                # print(location)
                file_has_content = False
                continue

            if file_has_content:
                InterfaceNames.append(filename[:-5])
                PacketCounts.append(packet_count)
                Throughtputs.append(throughtput)

                dst = "logs/" + filename[:-5] +".json"
                with open(dst, "w") as f:
                    print(location)
                    json.dump(PPS, f)
                    PPS = []
                    currentTime = 0

    for i in range(len(InterfaceNames)):
        print("Interface ", InterfaceNames[i], ": pkt count = %d, throughtput = %d" % (PacketCounts[i], Throughtputs[i]))  
