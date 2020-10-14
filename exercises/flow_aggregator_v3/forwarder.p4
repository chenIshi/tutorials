/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_CONTROL = 0x9F;
const bit<32> MAX_QUERY_ID = 1 << 16;
const bit<16> LOSS_PER_COUNT = 100;

const bit<32> I2E_CLONE_SESSION_ID = 5;

const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_NORMAL        = 0;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE = 1;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE  = 2;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_COALESCED     = 3;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RECIRC        = 4;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_REPLICATION   = 5;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RESUBMIT      = 6;

#define IS_RESUBMITTED(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_RESUBMIT)
#define IS_RECIRCULATED(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_RECIRC)
#define IS_I2E_CLONE(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE)
#define IS_E2E_CLONE(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE)
#define IS_REPLICATED(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_REPLICATION)

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
    bit <1> flagOverflow;
    bit <2> flagCleanup;
    bit<21> flowCount;
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
    // queryCounter store querycount in both monitor and aggregator
    register<bit<21>>(MAX_QUERY_ID) queryCounters;
    /* Both acked_monitor_number and last_seen_timestamp is for aggregator*/
    register <bit <8>> (MAX_QUERY_ID) acked_monitor_number;
    /* last_seen_timestamp is used to detect retransmittion of controller */
    register <bit<16>> (MAX_QUERY_ID) last_seen_timestamp;

    register <bit<16>> (1) loss_counter;

    /* reg_count acted as buffer
        but behaves differently between monitors and aggregators */
    bit<21> reg_count = 0;
    /* ctrl_addr/ctrl_mac is temp buffer for monitor */
    ip4Addr_t ctrl_addr;
    bit<48> ctrl_mac;
    /* control_drop is a drop label for some control packet*/
    bit<1> control_drop = 0;

    /*work-around for target (Conditional execution in actions is not supported)*/
    /* aggr_query_id means there is no match, otherwise aggr is triggered*/
    bit <16> aggr_query_id = 0;
    /* isAskingForResponse = 2 for monitors,  1 for aggregators, 0 for not responsing */
    bit <2> isAskingForResponse = 0;

    bit <8> seen_monNum;
    bit <8> total_monNum = 0;
    bit <16> temp_timestamp;
    bit <21> temp_count;
    ip4Addr_t temp_aggregator_ip = 0;

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

    action ipv4_response(bit<1> isMonitor) {
        isAskingForResponse = ((bit<2>) isMonitor ) + 1;
        /*
        queryCounters.read(reg_count, (bit<32>)hdr.myControl.queryID);

        hdr.myControl.flowCount = reg_count + 2;

        ctrl_addr = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = ctrl_addr;

        ctrl_mac = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr= hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr= ctrl_mac;

        standard_metadata.egress_spec=standard_metadata.ingress_port;
        */
    }

    action ipv4_aggregation(bit<16> queryID, ip4Addr_t aggregator_ip) {
        /*
        bit <8> seen_monNum;
        bit <16> temp_timestamp;
        bit <16> temp_count;
        */

        /* if the aggregator is responsible for the query */
        if (hdr.myControl.queryID == queryID) {
            aggr_query_id = queryID;
            temp_aggregator_ip = aggregator_ip;
        }
    }

    table control_handler {
        key = {
            hdr.ipv4.dstAddr: exact;
            hdr.myControl.queryID: exact;
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

    action doCheck(bit<8> monitor_num) {
        total_monNum = monitor_num;
    }

    table check_aggregate_satisfied {
        key = {
            hdr.myControl.queryID: exact;
        }
        actions = {
            NoAction;
            doCheck;
        }
        size = 1024;
        default_action = NoAction();
    }

    // ---- main ----

    apply {
        bit<16> temp_loss_count;
        bit<21> aggregate_summand;
        loss_counter.read(temp_loss_count, 0);
        loss_counter.write(0, temp_loss_count + 1);

        if (temp_loss_count > LOSS_PER_COUNT) {
            mark_to_drop(standard_metadata);
            loss_counter.write(0, 0);
        } else {
            if (hdr.ipv4.isValid()) {
                // decide its ip route first
                // however, not modified only if destination is itself
                ipv4_lpm.apply();

                // count passed flow if query is assigned
                ipv4_count.apply();

                // if it is a control plane packet
                if (hdr.myControl.isValid()) {
                    // acted a preconfig to see what to do next, response or aggregate or nothing
                    control_handler.apply();

                    // do response
                    if (isAskingForResponse > 0) {
                        // this is a aggregator
                        if (isAskingForResponse == 1) {
                            // clone3(CloneType.I2E, I2E_CLONE_SESSION_ID, standard_metadata);
                            // clone3(CloneType.I2E, I2E_CLONE_SESSION_ID, standard_metadata);
                            standard_metadata.mcast_grp = 1;
                        // this is a monitor
                        } else if (isAskingForResponse == 2) {
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
                    }
                    // do aggregate
                    if (aggr_query_id > 0) {
                        last_seen_timestamp.read(temp_timestamp, (bit<32>)aggr_query_id);
                        if (temp_timestamp != hdr.myControl.timestamp) {
                            queryCounters.write((bit<32>)aggr_query_id, 0);
                            acked_monitor_number.write((bit<32>)aggr_query_id, 0);
                            last_seen_timestamp.write((bit<32>)aggr_query_id, hdr.myControl.timestamp);
                        }

                        queryCounters.read(temp_count, (bit<32>)aggr_query_id);
                        aggregate_summand = temp_count + hdr.myControl.flowCount;
                        // check if it is overflowed
                        if (aggregate_summand < 5 || aggregate_summand < hdr.myControl.flowCount) {
                            hdr.myControl.flagOverflow = 1;
                        }
                        queryCounters.write((bit<32>)aggr_query_id, temp_count + hdr.myControl.flowCount);
                        acked_monitor_number.read(seen_monNum, (bit<32>)aggr_query_id);
                        acked_monitor_number.write((bit<32>)aggr_query_id, seen_monNum+1);

                        check_aggregate_satisfied.apply();

                        if (total_monNum > 0 && seen_monNum + 1 >= total_monNum) {
                            queryCounters.read(hdr.myControl.flowCount, (bit<32>)aggr_query_id);
                            hdr.ipv4.srcAddr = temp_aggregator_ip;
                            queryCounters.write((bit<32>)aggr_query_id, 0);
                            acked_monitor_number.write((bit<32>)aggr_query_id, 0);
                        } else {
                            control_drop = 1;
                        }
                    }

                    /* make sure it is initialized*/
                    aggr_query_id = 0;

                    if (control_drop == 1) {
                        mark_to_drop(standard_metadata);
                        control_drop = 0;
                    }
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

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action doUnpack(ip4Addr_t monitorAddr) {
        /* forward the generated packet with right IP addr*/
        hdr.ipv4.dstAddr = monitorAddr;
    }

    table aggr_unpack {
        key = {
            standard_metadata.egress_port: exact;
        }
        actions = {
            NoAction;
            doUnpack;
        }
        size = 512;
        default_action = NoAction();
    }
    
    apply { 
        /*
        if (standard_metadata.egress_port == standard_metadata.ingress_port) {
            drop();
        }
        */
        if (IS_REPLICATED(standard_metadata)) {
            aggr_unpack.apply();
        }
    }
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
