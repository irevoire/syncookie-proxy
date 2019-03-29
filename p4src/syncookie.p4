/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> L2_LEARN_ETHER_TYPE = 0x1234;
const bit<16> LEARN_COOKIE = 0xF00D;

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
	bit<6>    dscp;
	bit<2>    ecn;
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
	bit<32> ackNo; // will carry the cookie
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

header cpu_t {
	// router
	bit<16>   ingress_port;
	macAddr_t macAddr;
	// synCookie Proxy
	ip4Addr_t srcAddr;
	ip4Addr_t dstAddr;
	bit<16>   srcPort;
	bit<16>   dstPort;
}

struct metadata {
	bit<1>  update_route;
	bit<1>  good_cookie;

	bit<9>  ingress_port;
	bit<32> cookie;
}

struct headers {
	ethernet_t ethernet;
	ipv4_t     ipv4;
	tcp_t      tcp;
	cpu_t      cpu;
}

/*************************************************************************
 *********************** P A R S E R  ***********************************
 *************************************************************************/

parser MyParser(packet_in packet,
		out headers hdr,
		inout metadata meta,
		inout standard_metadata_t standard_metadata) {
	state start {
		transition ethernet;
	}

	state ethernet {
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType) {
			TYPE_IPV4: ipv4;
			default: accept;
		}
	}

	state ipv4 {
		packet.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol) {
			6: parse_tcp;
			default: accept;
		}
	}

	state parse_tcp {
		packet.extract(hdr.tcp);
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
	action drop() {
		mark_to_drop();
	}

	action mac_learn() {
		meta.ingress_port = standard_metadata.ingress_port;
		meta.update_route = 1;
		clone3(CloneType.I2E, 100, meta);
	}

	table smac {
		key = {
			hdr.ethernet.srcAddr: exact;
		}

		actions = {
			mac_learn;
			NoAction;
		}
		size = 256;
		default_action = mac_learn;
	}

	action forward(bit<9> egress_port) {
		standard_metadata.egress_spec = egress_port;
	}

	table dmac {
		key = {
			hdr.ethernet.dstAddr: exact;
		}

		actions = {
			forward;
			NoAction;
		}
		size = 256;
		default_action = NoAction;
	}

	action set_mcast_grp(bit<16> mcast_grp) {
		standard_metadata.mcast_grp = mcast_grp;
	}

	table broadcast {
		key = {
			standard_metadata.ingress_port: exact;
		}

		actions = {
			set_mcast_grp;
			NoAction;
		}
		size = 256;
		default_action = NoAction;
	}

	action compute_cookie() {
		meta.cookie = (bit<32>)hdr.tcp.srcPort;
		meta.cookie = (meta.cookie << 16) ^ (bit<32>) hdr.tcp.dstPort;
		meta.cookie = meta.cookie ^ hdr.ipv4.srcAddr;
		meta.cookie = meta.cookie ^ hdr.ipv4.dstAddr;
	}

	table tcp_forward {
		key = {
			meta.cookie: exact;
		}
		actions = {
			NoAction;
			drop;
		}
		size = 256;
		default_action = drop;
	}

	action handle_syn() {
		// first we send the packet back to the source
		standard_metadata.egress_spec = standard_metadata.ingress_port;
		// increment seqNo and move it to ackNo
		hdr.tcp.ackNo = hdr.tcp.seqNo + 1;
		// store the cookie into our seqNo
		hdr.tcp.seqNo = meta.cookie;
		// set the tcp flags to SYN-ACK
		hdr.tcp.ack = 1;
		// swap src / dst port
		bit<16> port = hdr.tcp.srcPort;
		hdr.tcp.srcPort = hdr.tcp.dstPort;
		hdr.tcp.dstPort = hdr.tcp.srcPort;
	}

	action handle_ack() {
		// we must save the connection as a safe
		meta.good_cookie = 1;
		clone3(CloneType.I2E, 100, meta);

		// we do nothing else because we expect the recipient
		// to handle everything (increment ack, swap port etc...)
	}

	apply {
		smac.apply();
		if (!dmac.apply().hit) {
			broadcast.apply();
		}
		if (hdr.tcp.isValid()) {
			compute_cookie();
			if (!tcp_forward.apply().hit) {
				// you won't steal my cookie!
				if (hdr.tcp.syn == 1 && hdr.tcp.ack == 1)
					drop();
				// we should get a syn
				else if (hdr.tcp.syn == 1)
					handle_syn();
				// or has the communication already started?
				else if ( (hdr.tcp.ack == 1) &&
						((hdr.tcp.ackNo - 1) == meta.cookie))
					handle_ack();
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
	apply {
		// If ingress clone
		if (standard_metadata.instance_type == 1) {
			hdr.cpu.setValid();
			if (meta.update_route == 1) {
				hdr.cpu.macAddr = hdr.ethernet.srcAddr;
				hdr.cpu.ingress_port = (bit<16>)meta.ingress_port;
				hdr.ethernet.etherType = L2_LEARN_ETHER_TYPE;
				truncate((bit<32>)22); //ether+cpu header
			}
			if (meta.good_cookie == 1) {
				hdr.cpu.srcAddr = hdr.ipv4.srcAddr;
				hdr.cpu.dstAddr = hdr.ipv4.dstAddr;
				hdr.cpu.srcPort = hdr.tcp.srcPort;
				hdr.cpu.dstPort = hdr.tcp.dstPort;

				hdr.ethernet.etherType = LEARN_COOKIE;
			}
		}
	}
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
	apply {

	}
}

/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
	apply {
		//parsed headers have to be added again into the packet.
		packet.emit(hdr.ethernet);
		packet.emit(hdr.ipv4);
		packet.emit(hdr.tcp);

		packet.emit(hdr.cpu);
	}
}

/*************************************************************************
 ***********************  S W I T C H  *******************************
 *************************************************************************/

//switch architecture
	V1Switch(
			MyParser(),
			MyVerifyChecksum(),
			MyIngress(),
			MyEgress(),
			MyComputeChecksum(),
			MyDeparser()
		) main;
