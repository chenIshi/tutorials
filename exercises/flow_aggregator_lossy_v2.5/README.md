# Reliable Flow Aggregation (With Faulty Switch)

## Introduction

## Quick Run

> (sudo iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP)

    This is used to stop controller from keep generating misguiding ICMP proto unreachable
    (since we are using a non-existed proto number, it is natural for such warning)
    However, it seems not working (https://serverfault.com/questions/522709/disable-icmp-unreachable-replies)

> make

> ./mycontroller (in another terminal)

> h1 sudo python2 doAggregate.py

    ... wait about 5 mins
    (for contrast exp, swap `doAggregate.py` to `noAggregate.py`)

> *ctrl + d* (leave mininet env)

> python analyzer.py

