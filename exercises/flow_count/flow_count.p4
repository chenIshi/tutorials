/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;
const bit<16> TYPE_CONTROL = 250;
const bit<32> SUBNET_MASK = 0xFFFFFF00;

#define BLOOM_FILTER_ENTRIES 4096
#define COUNT_WIDTH 8
#define IP_WIDTH 32

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

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header control_t {
    ip4Addr_t src;
    ip4Addr_t dst;
    bit<COUNT_WIDTH> flow_count;
}

struct metadata {
   macAddr_t temp_mac;
   ip4Addr_t temp_ip;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    control_t control_hdr;
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
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: tcp;
            TYPE_CONTROL: parse_control_msg;
            default: accept;
        }
    }

    state tcp {
       packet.extract(hdr.tcp);
       transition accept;
    }

    state parse_control_msg {
        packet.extract(hdr.control_hdr);
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

    register<bit<COUNT_WIDTH>>(BLOOM_FILTER_ENTRIES) flow_counts;
    bit<32> count_index;
    bit<COUNT_WIDTH> count_reg;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action compute_hashes(ip4Addr_t srcAddr, ip4Addr_t dstAddr) {
        hash(count_index, HashAlgorithm.crc16, (bit<32>)0, 
						{srcAddr, dstAddr},
                                                           (bit<32>)BLOOM_FILTER_ENTRIES);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        // we should forward data-plane packets normally
        if (!hdr.control_hdr.isValid()) {
            standard_metadata.egress_spec = port;
            hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
            hdr.ethernet.dstAddr = dstAddr;
            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        // and we shall send (echo) back control-plane packets
        } else {
            standard_metadata.egress_spec = standard_metadata.ingress_port;
            // swap src mac with dst mac
            meta.temp_mac = hdr.ethernet.srcAddr;
            hdr.ethernet.srcAddr =  hdr.ethernet.dstAddr;
            hdr.ethernet.dstAddr = meta.temp_mac;

            // swap src ip with dst ip
            meta.temp_ip = hdr.ipv4.srcAddr;
            hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
            hdr.ipv4.dstAddr = meta.temp_ip;

            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        }
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
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()){
            ipv4_lpm.apply();
            // it's a normal data-plane packet
            if (hdr.tcp.isValid()){
                compute_hashes(hdr.ipv4.srcAddr & SUBNET_MASK, hdr.ipv4.dstAddr & SUBNET_MASK);
                flow_counts.read(count_reg, count_index);
                flow_counts.write(count_index, count_reg + 1);
            }

            // it's a control-plane packet
            if (hdr.control_hdr.isValid()) {
                compute_hashes(hdr.control_hdr.src & SUBNET_MASK, hdr.control_hdr.dst & SUBNET_MASK);
                flow_counts.read(count_reg, count_index);
                hdr.control_hdr.flow_count = count_reg;
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
        packet.emit(hdr.tcp);
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
