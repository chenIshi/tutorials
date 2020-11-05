# Reliable Flow Aggregation (With Faulty Switch)

## Introduction
We experiment the aggregation of network monitor message on the programmable switch.
The switch itself is faulty (some innate packet-drop rate, configurable), and we manage to limit the throughput of all link to be unaffected by the number of monitors, that is, elimates the incast flow in network monitorship.


## Quick Run

> sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
> sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1

It is strongly recommanded to disable IPv6 config first, since it will send stupid ICMP protocol unreachable after receiving our self-crafted 159 protocol
(It is natural to have such warning since ip protocol isn't existed in current usage, however it will mess up our throughput)

> make

This will make a mininet environment with BMv2 switches for you, with an interactive shell

> ./mycontroller (in another terminal)

This setups the control plane of BMv2 swithes all at the same time, via the p4runtime tool.

> h2 ping h3 -w 300 -i 0.01 -q &

You might need to establish some background pinging flow

> h1 sudo python2 doAggregate.py

Type those command on the mininet shell, mainly is to ask h1 (the controller) to start polling

    ... wait about 5 mins

> *ctrl + d* (leave mininet env)

Leave the test environment

> python analyzer.py

This will generate a full report of thoughtput and packet count, detailed of PPS(Packet Per Second) will be shown in `/logs`
