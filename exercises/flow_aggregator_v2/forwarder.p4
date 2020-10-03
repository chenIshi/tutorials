/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_CONTROL = 0x9F;
const bit<32> MAX_QUERY_ID = 1 << 16;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header myControl_t {
    bit<16> queryID;
    /* Number of monitor in that query*/
    bit<8> monNum;
    bit<16> flowCount;
    bit<16> timestamp;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    myControl_t myControl;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }


    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_CONTROL: parse_myControl;
            default: accept;
        }
    }

    state parse_myControl {
        packet.extract(hdr.myControl);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // p416 doesn't allow to read counter in data plane
    register<bit<16>>(MAX_QUERY_ID) queryCounters;
    /* reg_count acted as buffer
        but behaves differently between monitors and aggregators */
    bit<16> reg_count = 0;
    /* ctrl_addr/ctrl_mac is temp buffer for monitor */
    ip4Addr_t ctrl_addr;
    bit<48> ctrl_mac;
    /* Both acked_monitor_number and last_seen_timestamp is for aggregator*/
    bit <8> acked_monitor_number = 0;
    /* last_seen_timestamp is used to detect retransmittion of controller */
    bit<16> last_seen_timestamp = 0;
    /* control_drop is a drop label for some control packet*/
    bit<1> control_drop = 0;

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    // record flow msg according to control plane config
    /* No forward if destined for self*/
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }


    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    // ---- pre-configed flow count with mini-controller ----

    action doCount(bit<16> queryID) {
        queryCounters.read(reg_count, (bit<32>)queryID);
        queryCounters.write((bit<32>)queryID, reg_count + 1);
    }

    table ipv4_count {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            doCount;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    // ---- control plane periodical msg ----

    action ipv4_response() {
        queryCounters.read(reg_count, (bit<32>)hdr.myControl.queryID);
        /* TODO: delete + 2 here (only for debugging)*/
        hdr.myControl.flowCount = reg_count + 2;

        /* send back to controller */
        ctrl_addr = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = ctrl_addr;

        ctrl_mac = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr= hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr= ctrl_mac;

        standard_metadata.egress_spec=standard_metadata.ingress_port;
    }

    action ipv4_aggregation(bit<16> queryID) {
        if (hdr.myControl.queryID == queryID) {

            if (last_seen_timestamp != hdr.myControl.timestamp) {
                /* clean-up for another round of aggregation */
                reg_count = 0;
                acked_monitor_number = 0;
		        last_seen_timestamp = hdr.myControl.timestamp;
            }
            reg_count = reg_count + hdr.myControl.flowCount;
            acked_monitor_number = acked_monitor_number + 1;

            /* Aggregation Complete */
            if (acked_monitor_number >= hdr.myControl.monNum) {
                hdr.myControl.flowCount = reg_count;
		        reg_count = 0;
		        acked_monitor_number = 0;
            } else {
                control_drop = 1;
            }
        }
    }

    table control_handler {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            drop;
            NoAction;
            ipv4_response;
            ipv4_aggregation;
        }
        size = 1024;
        default_action = NoAction();
    }

    // ---- main ----

    apply {
        if (hdr.ipv4.isValid()) {
            // decide its ip route first
            // however, not modified only if destination is itself
            ipv4_lpm.apply();

            // count passed flow if query is assigned
            ipv4_count.apply();

            // if it is a control plane packet
            if (hdr.myControl.isValid()) {
                control_handler.apply();

                if (control_drop == 1) {
                    mark_to_drop(standard_metadata);
                    control_drop = 0;
                }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.myControl);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
