#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
from time import sleep

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

def writeL2Forwarding(p4info_helper, switch, dst_ip_addr, dst_ip_mask, 
                    dst_mac_addr, dst_port):
    """
    Forward every packet except its dest is for the switch itself
    Potential packet drop for latter aggregation, but ignore it here
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, dst_ip_mask)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": dst_mac_addr,
            "port": dst_port,
        })

    switch.WriteTableEntry(table_entry)

def writeMonitoring(p4info_helper, switch, dst_ip_addr):
    """
    Monitor should response once destination is its (virtual) IP
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.control_handler",
        match_fields={
            "hdr.ipv4.dstAddr": dst_ip_addr
        },
        action_name="MyIngress.ipv4_response",
        action_params= { })

    switch.WriteTableEntry(table_entry)

def writeAggregating(p4info_helper, switch, dst_ip_addr):
    """
    Aggregator should response once destination is its (virtual) IP
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.control_handler",
        match_fields={
            "hdr.ipv4.dstAddr": dst_ip_addr
        },
        action_name="MyIngress.ipv4_aggregation",
        action_params= { })

    switch.WriteTableEntry(table_entry)

def writeFlowCountQuery(p4info_helper, switch, query_id, dst_ip_addr, dst_ip_mask):
    """
    Setup query config for monitors
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_count",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, dst_ip_mask)
        },
        action_name="MyIngress.doCount",
        action_params={
            "queryID": query_id,
        })
    
    switch.WriteTableEntry(table_entry)

def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print '\n----- Reading tables rules for %s -----' % sw.name
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            # TODO For extra credit, you can use the p4info_helper to translate
            #      the IDs in the entry to names
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print '%s: ' % table_name,
            for m in entry.match:
                print p4info_helper.get_match_field_name(table_name, m.field_id),
                print '%r' % (p4info_helper.get_match_field_value(m),),
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print '->', action_name,
            for p in action.params:
                print p4info_helper.get_action_param_name(action_name, p.param_id),
                print '%r' % p.value,
            print

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for switches;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')

        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')

        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')

        s4 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s4',
            address='127.0.0.1:50054',
            device_id=3,
            proto_dump_file='logs/s4-p4runtime-requests.txt')

        s5 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s5',
            address='127.0.0.1:50055',
            device_id=4,
            proto_dump_file='logs/s5-p4runtime-requests.txt')

        s6 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s6',
            address='127.0.0.1:50056',
            device_id=5,
            proto_dump_file='logs/s6-p4runtime-requests.txt')

        s7 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s7',
            address='127.0.0.1:50057',
            device_id=6,
            proto_dump_file='logs/s7-p4runtime-requests.txt')

        s8 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s8',
            address='127.0.0.1:50058',
            device_id=7,
            proto_dump_file='logs/s8-p4runtime-requests.txt')

        s9 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s9',
            address='127.0.0.1:50059',
            device_id=8,
            proto_dump_file='logs/s9-p4runtime-requests.txt')

        s10 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s10',
            address='127.0.0.1:50060',
            device_id=9,
            proto_dump_file='logs/s10-p4runtime-requests.txt')

        s11 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s11',
            address='127.0.0.1:50061',
            device_id=10,
            proto_dump_file='logs/s11-p4runtime-requests.txt')

        s12 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s12',
            address='127.0.0.1:50062',
            device_id=11,
            proto_dump_file='logs/s12-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()
        s4.MasterArbitrationUpdate()
        s5.MasterArbitrationUpdate()
        s6.MasterArbitrationUpdate()
        s7.MasterArbitrationUpdate()
        s8.MasterArbitrationUpdate()
        s9.MasterArbitrationUpdate()
        s10.MasterArbitrationUpdate()
        s11.MasterArbitrationUpdate()
        s12.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s1"
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s2"
        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s3"
        s4.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s4"

        s5.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s5"
        s6.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s6"
        s7.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s7"
        s8.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s8"

        s9.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s9"
        s10.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s10"
        s11.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s11"
        s12.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s12"
        
        # Write l2 forwarding rule
        ## data plane routing
        ### switches to hosts
        writeL2Forwarding(p4info_helper, switch=s1, dst_ip_addr="10.0.1.1", dst_ip_mask=32,
                    dst_mac_addr="08:00:00:00:01:11", dst_port=1)
        writeL2Forwarding(p4info_helper, switch=s1, dst_ip_addr="10.0.1.2", dst_ip_mask=32,
                    dst_mac_addr="08:00:00:00:02:22", dst_port=2)
        writeL2Forwarding(p4info_helper, switch=s1, dst_ip_addr="10.1.0.0", dst_ip_mask=16,
                    dst_mac_addr="08:00:00:00:03:00", dst_port=3)

        writeL2Forwarding(p4info_helper, switch=s2, dst_ip_addr="10.0.2.1", dst_ip_mask=32,
                    dst_mac_addr="08:00:00:00:03:33", dst_port=1)
        writeL2Forwarding(p4info_helper, switch=s2, dst_ip_addr="10.0.2.2", dst_ip_mask=32,
                    dst_mac_addr="08:00:00:00:04:44", dst_port=2)
        writeL2Forwarding(p4info_helper, switch=s2, dst_ip_addr="10.1.0.0", dst_ip_mask=16,
                    dst_mac_addr="08:00:00:00:03:00", dst_port=4)

        writeL2Forwarding(p4info_helper, switch=s5, dst_ip_addr="10.1.1.1", dst_ip_mask=32,
                    dst_mac_addr="08:00:00:00:11:11", dst_port=1)
        writeL2Forwarding(p4info_helper, switch=s5, dst_ip_addr="10.1.1.2", dst_ip_mask=32,
                    dst_mac_addr="08:00:00:00:12:22", dst_port=2)
        writeL2Forwarding(p4info_helper, switch=s5, dst_ip_addr="10.0.0.0", dst_ip_mask=16,
                    dst_mac_addr="08:00:00:00:07:00", dst_port=3)

        writeL2Forwarding(p4info_helper, switch=s6, dst_ip_addr="10.1.2.1", dst_ip_mask=32,
                    dst_mac_addr="08:00:00:00:13:33", dst_port=1)
        writeL2Forwarding(p4info_helper, switch=s6, dst_ip_addr="10.1.2.2", dst_ip_mask=32,
                    dst_mac_addr="08:00:00:00:14:44", dst_port=2)
        writeL2Forwarding(p4info_helper, switch=s6, dst_ip_addr="10.0.0.0", dst_ip_mask=16,
                    dst_mac_addr="08:00:00:00:07:00", dst_port=4)

        ### switches to switches

        writeL2Forwarding(p4info_helper, switch=s3, dst_ip_addr="10.0.1.0", dst_ip_mask=24,
                    dst_mac_addr="08:00:00:00:01:00", dst_port=1)
        writeL2Forwarding(p4info_helper, switch=s3, dst_ip_addr="10.0.2.0", dst_ip_mask=24,
                    dst_mac_addr="08:00:00:00:02:00", dst_port=2)
        writeL2Forwarding(p4info_helper, switch=s3, dst_ip_addr="10.1.0.0", dst_ip_mask=16,
                    dst_mac_addr="08:00:00:00:0a:00", dst_port=4)

        writeL2Forwarding(p4info_helper, switch=s10, dst_ip_addr="10.0.0.0", dst_ip_mask=16,
                    dst_mac_addr="08:00:00:00:03:00", dst_port=1)
        writeL2Forwarding(p4info_helper, switch=s10, dst_ip_addr="10.1.0.0", dst_ip_mask=16,
                    dst_mac_addr="08:00:00:00:07:00", dst_port=2)

        writeL2Forwarding(p4info_helper, switch=s7, dst_ip_addr="10.1.1.0", dst_ip_mask=24,
                    dst_mac_addr="08:00:00:00:05:00", dst_port=1)
        writeL2Forwarding(p4info_helper, switch=s7, dst_ip_addr="10.1.2.0", dst_ip_mask=24,
                    dst_mac_addr="08:00:00:00:06:00", dst_port=2)
        writeL2Forwarding(p4info_helper, switch=s7, dst_ip_addr="10.0.0.0", dst_ip_mask=16,
                    dst_mac_addr="08:00:00:00:0a:00", dst_port=3)

        ## data plane routing
        writeL2Forwarding(p4info_helper, switch=s1, dst_ip_addr="10.2.10.3", dst_ip_mask=32,
                    dst_mac_addr="08:00:00:00:03:00", dst_port=3)
        writeL2Forwarding(p4info_helper, switch=s1, dst_ip_addr="10.2.10.2", dst_ip_mask=32,
                    dst_mac_addr="08:00:00:00:03:00", dst_port=3)
        writeL2Forwarding(p4info_helper, switch=s1, dst_ip_addr="10.2.12.0", dst_ip_mask=24,
                    dst_mac_addr="08:00:00:00:03:00", dst_port=3)
        writeL2Forwarding(p4info_helper, switch=s1, dst_ip_addr="10.2.11.0", dst_ip_mask=24,
                    dst_mac_addr="08:00:00:00:03:00", dst_port=3)

        writeL2Forwarding(p4info_helper, switch=s2, dst_ip_addr="10.2.10.3", dst_ip_mask=32,
                    dst_mac_addr="08:00:00:00:03:00", dst_port=4)
        writeL2Forwarding(p4info_helper, switch=s2, dst_ip_addr="10.2.10.1", dst_ip_mask=32,
                    dst_mac_addr="08:00:00:00:03:00", dst_port=4)
        writeL2Forwarding(p4info_helper, switch=s2, dst_ip_addr="10.2.12.0", dst_ip_mask=24,
                    dst_mac_addr="08:00:00:00:03:00", dst_port=4)
        writeL2Forwarding(p4info_helper, switch=s2, dst_ip_addr="10.2.11.0", dst_ip_mask=24,
                    dst_mac_addr="08:00:00:00:03:00", dst_port=4)

        writeL2Forwarding(p4info_helper, switch=s3, dst_ip_addr="10.2.10.1", dst_ip_mask=32,
                    dst_mac_addr="08:00:00:00:01:00", dst_port=1)
        writeL2Forwarding(p4info_helper, switch=s3, dst_ip_addr="10.2.10.2", dst_ip_mask=32,
                    dst_mac_addr="08:00:00:00:02:00", dst_port=2)
        writeL2Forwarding(p4info_helper, switch=s3, dst_ip_addr="10.2.12.0", dst_ip_mask=24,
                    dst_mac_addr="08:00:00:00:0a:00", dst_port=4)
        writeL2Forwarding(p4info_helper, switch=s3, dst_ip_addr="10.2.11.0", dst_ip_mask=24,
                    dst_mac_addr="08:00:00:00:0a:00", dst_port=4)

        writeL2Forwarding(p4info_helper, switch=s10, dst_ip_addr="10.2.10.0", dst_ip_mask=24,
                    dst_mac_addr="08:00:00:00:03:00", dst_port=1)
        writeL2Forwarding(p4info_helper, switch=s10, dst_ip_addr="10.2.11.0", dst_ip_mask=24,
                    dst_mac_addr="08:00:00:00:07:00", dst_port=2)

        writeL2Forwarding(p4info_helper, switch=s7, dst_ip_addr="10.2.11.5", dst_ip_mask=32,
                    dst_mac_addr="08:00:00:00:05:00", dst_port=1)
        writeL2Forwarding(p4info_helper, switch=s7, dst_ip_addr="10.2.11.6", dst_ip_mask=32,
                    dst_mac_addr="08:00:00:00:06:00", dst_port=2)
        writeL2Forwarding(p4info_helper, switch=s7, dst_ip_addr="10.2.12.0", dst_ip_mask=24,
                    dst_mac_addr="08:00:00:00:0a:00", dst_port=3)
        writeL2Forwarding(p4info_helper, switch=s7, dst_ip_addr="10.2.10.0", dst_ip_mask=24,
                    dst_mac_addr="08:00:00:00:0a:00", dst_port=3)

        writeL2Forwarding(p4info_helper, switch=s5, dst_ip_addr="10.2.11.7", dst_ip_mask=32,
                    dst_mac_addr="08:00:00:00:07:00", dst_port=3)
        writeL2Forwarding(p4info_helper, switch=s5, dst_ip_addr="10.2.11.6", dst_ip_mask=32,
                    dst_mac_addr="08:00:00:00:07:00", dst_port=3)
        writeL2Forwarding(p4info_helper, switch=s5, dst_ip_addr="10.2.12.0", dst_ip_mask=24,
                    dst_mac_addr="08:00:00:00:07:00", dst_port=3)
        writeL2Forwarding(p4info_helper, switch=s5, dst_ip_addr="10.2.10.0", dst_ip_mask=24,
                    dst_mac_addr="08:00:00:00:07:00", dst_port=3)

        writeL2Forwarding(p4info_helper, switch=s6, dst_ip_addr="10.2.11.7", dst_ip_mask=32,
                    dst_mac_addr="08:00:00:00:07:00", dst_port=4)
        writeL2Forwarding(p4info_helper, switch=s6, dst_ip_addr="10.2.11.5", dst_ip_mask=32,
                    dst_mac_addr="08:00:00:00:07:00", dst_port=4)
        writeL2Forwarding(p4info_helper, switch=s6, dst_ip_addr="10.2.12.0", dst_ip_mask=24,
                    dst_mac_addr="08:00:00:00:07:00", dst_port=4)
        writeL2Forwarding(p4info_helper, switch=s6, dst_ip_addr="10.2.10.0", dst_ip_mask=24,
                    dst_mac_addr="08:00:00:00:07:00", dst_port=4)

        ## Also start handle it if it destined for here
        writeMonitoring(p4info_helper, switch=s5, dst_ip_addr="10.2.11.5")
        writeMonitoring(p4info_helper, switch=s6, dst_ip_addr="10.2.11.6")

        # Write inspected flow config to monitor switches
        writeFlowCountQuery(p4info_helper, switch=s5, query_id=1, dst_ip_addr="10.0.1.0", dst_ip_mask=24)
        writeFlowCountQuery(p4info_helper, switch=s6, query_id=1, dst_ip_addr="10.0.1.0", dst_ip_mask=24)

        # Write the aggregated flow config to aggr switches
        writeAggregating(p4info_helper, switch=s7, dst_ip_addr="10.0.1.1")

        # TODO Uncomment the following two lines to read table entries from s1 and s2
        readTableRules(p4info_helper, s5)
        readTableRules(p4info_helper, s6)

        # Print the tunnel counters every 2 seconds
        while True:
            sleep(2)
            print '\n----- Sleeping -----'

    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/forwarder.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/forwarder.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
