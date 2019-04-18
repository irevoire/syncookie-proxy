/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> L2_LEARN_ETHER_TYPE = 0x1234;
const bit<16> SAVE_PRE_CONNECTION = 0xF00D;
const bit<16> SAVE_CONNECTION = 0xCACA;

/*************************************************************************
 *********************** H E A D E R S  ***********************************
 *************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
	macAddr_t dstAddr;   // 6
	macAddr_t srcAddr;   // 6
	bit<16>   etherType; // 2
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

header cpu_route_t {
	// router
	bit<16>   ingress_port; // 2
	macAddr_t macAddr;      // 6
}

header cpu_connection_t {
	// save connection
	ip4Addr_t srcAddr; // 4
	ip4Addr_t dstAddr; // 4
	bit<16>   srcPort; // 2
	bit<16>   dstPort; // 2
	bit<32>   offset;  // 4
}

struct metadata {
	// condition
	bit<1>  update_route;
	bit<1>  save_pre_connection;
	bit<1>  save_connection;

	// learn routing
	bit<9>  ingress_port;

	// learn connection
	bit<32> offset;

	// metadata
	bit<32> cookie;
	bit<96> connection; // two ip address (32 * 2) + two ports (16 * 2)
}

struct headers {
	ethernet_t ethernet;
	ipv4_t     ipv4;
	tcp_t      tcp;

	cpu_route_t      cpu_route;
	cpu_connection_t     cpu_connection;
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

	// ============ SYN COOKIE PROXY ============
	action compute_connection() {
		meta.connection = (bit<96>)hdr.ipv4.srcAddr;
		meta.connection = meta.connection << 32;
		meta.connection = meta.connection | (bit<96>)hdr.ipv4.dstAddr;
		meta.connection = meta.connection << 16;
		meta.connection = meta.connection | (bit<96>)hdr.tcp.srcPort;
		meta.connection = meta.connection << 16;
		meta.connection = meta.connection | (bit<96>)hdr.tcp.dstPort;
	}

	action compute_cookie() {
		meta.cookie = (bit<32>)hdr.tcp.srcPort;
		meta.cookie = (meta.cookie << 16) | (bit<32>) hdr.tcp.dstPort;
		meta.cookie = meta.cookie ^ hdr.ipv4.srcAddr;
		meta.cookie = meta.cookie ^ hdr.ipv4.dstAddr;
	}

	action update_seqNo(bit<32> offset) {
		bit<32> checksum = ~offset;
		checksum = ((checksum & 0xFFFF0000) >> 16) + checksum & 0x0000FFFF;
		checksum = checksum + (bit<32>) hdr.tcp.checksum;
		checksum = checksum + 1; // magic
		checksum = ((checksum & 0xFFFF0000) >> 16) + checksum & 0x0000FFFF;
		checksum = ((checksum & 0xFFFF0000) >> 16) + checksum & 0x0000FFFF;
		hdr.tcp.checksum = (bit<16>) checksum;

		hdr.tcp.seqNo = hdr.tcp.seqNo + offset;
	}

	action update_ackNo(bit<32> offset) {
		bit<32> checksum = offset;
		checksum = ((checksum & 0xFFFF0000) >> 16) + checksum & 0x0000FFFF;
		checksum = checksum + (bit<32>) hdr.tcp.checksum;
		checksum = ((checksum & 0xFFFF0000) >> 16) + checksum & 0x0000FFFF;
		checksum = ((checksum & 0xFFFF0000) >> 16) + checksum & 0x0000FFFF;
		hdr.tcp.checksum = (bit<16>) checksum;

		hdr.tcp.ackNo = hdr.tcp.ackNo - offset;
	}

	table tcp_forward {
		key = {
			meta.connection: exact;
		}
		actions = {
			update_seqNo;
			update_ackNo;
			NoAction;
		}
		size = 256;
		default_action = NoAction;
	}

	action handle_syn() {
		// =========== PHY ============
		// send the packet back to the source
		standard_metadata.egress_spec = standard_metadata.ingress_port;

		// =========== MAC ============
		// swap src / dst addr
		macAddr_t macaddr = hdr.ethernet.srcAddr;
		hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
		hdr.ethernet.dstAddr = macaddr;

		// =========== IP ============
		// swap src / dst addr
		ip4Addr_t ipaddr = hdr.ipv4.srcAddr;
		hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
		hdr.ipv4.dstAddr = ipaddr;

		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

		// =========== TCP ============
		// first we'll update the checksum
		bit<32> checksum = ~meta.cookie;
		checksum = ((checksum & 0xFFFF0000) >> 16) + checksum & 0x0000FFFF;
		checksum = checksum + (bit<32>) hdr.tcp.checksum;
		checksum = checksum + 0xFFEF; // MAGIC
		checksum = ((checksum & 0xFFFF0000) >> 16) + checksum & 0x0000FFFF;
		checksum = ((checksum & 0xFFFF0000) >> 16) + checksum & 0x0000FFFF;
		hdr.tcp.checksum = (bit<16>) checksum;

		// increment seqNo and move it to ackNo
		hdr.tcp.ackNo = hdr.tcp.seqNo + 1;
		// store the cookie into our seqNo
		hdr.tcp.seqNo = meta.cookie;
		// set the tcp flags to SYN-ACK
		hdr.tcp.ack = 1;

		// swap src / dst port
		bit<16> tcpport = hdr.tcp.srcPort;
		hdr.tcp.srcPort = hdr.tcp.dstPort;
		hdr.tcp.dstPort = tcpport;
	}

	/*
	 * We have validated the cookie. A is a real client.
	 * Now we want to start a new connection with B, we send
	 * him a new SYN and save his Sequence Number for later.
	 */
	action handle_ack() {
		// =========== CPU ============
		meta.save_pre_connection = 1;
		meta.offset = hdr.tcp.ackNo - 1; // we could also get the cookie
		clone3(CloneType.I2E, 100, meta);

		// =========== IP ============
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

		// =========== TCP ============
		bit<32> checksum = hdr.tcp.ackNo;
		checksum = ((checksum & 0xFFFF0000) >> 16) + checksum & 0x0000FFFF;
		checksum = checksum + (bit<32>) hdr.tcp.checksum;
		checksum = checksum + 0x000F; // MAGIC
		checksum = ((checksum & 0xFFFF0000) >> 16) + checksum & 0x0000FFFF;
		checksum = ((checksum & 0xFFFF0000) >> 16) + checksum & 0x0000FFFF;
		hdr.tcp.checksum = (bit<16>) checksum;

		hdr.tcp.seqNo = hdr.tcp.seqNo - 1;
		hdr.tcp.ackNo = 0; // remove the ack (cookie)

		hdr.tcp.ack = 0;
		hdr.tcp.syn = 1;
	}

	action handle_syn_ack(bit<32> old_ackNo) {
		// =========== CPU ============
		meta.save_connection = 1;
		meta.offset = old_ackNo - hdr.tcp.seqNo - 1; // -1 for alignment
		clone3(CloneType.I2E, 100, meta);

		// =========== PHY ============
		standard_metadata.egress_spec = standard_metadata.ingress_port;

		// =========== MAC ============
		// swap src / dst addr
		macAddr_t macaddr = hdr.ethernet.srcAddr;
		hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
		hdr.ethernet.dstAddr = macaddr;

		// =========== IP ============
		// swap src / dst addr
		ip4Addr_t ipaddr = hdr.ipv4.srcAddr;
		hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
		hdr.ipv4.dstAddr = ipaddr;

		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

		// =========== TCP ============
		bit<32> checksum = (bit<32>) hdr.tcp.checksum;
		checksum = checksum + 1; // seqNo + 1
		checksum = ((checksum & 0xFFFF0000) >> 16) + checksum & 0x0000FFFF;
		hdr.tcp.checksum = (bit<16>) checksum;

		// swap seqNo et ackNo
		bit<32> seqNo = hdr.tcp.seqNo;
		hdr.tcp.seqNo = hdr.tcp.ackNo;
		hdr.tcp.ackNo = seqNo + 1;

		hdr.tcp.ack = 1; // useless
		hdr.tcp.syn = 0;

		// swap src / dst port
		bit<16> tcpport = hdr.tcp.srcPort;
		hdr.tcp.srcPort = hdr.tcp.dstPort;
		hdr.tcp.dstPort = tcpport;
	}

	table syn_ack {
		key = {
			meta.connection: exact;
		}

		actions = {
			handle_syn_ack;
			drop;
		}
		size = 256;
		default_action = drop;
	}

	apply {
		smac.apply();
		if (!dmac.apply().hit) {
			broadcast.apply();
		}
		if (hdr.tcp.isValid()) {
			compute_connection();
			if (!tcp_forward.apply().hit) {
				compute_cookie();
				// you won't steal my cookie!
				// if SYN-ACK or any other flags, drop
				if (hdr.tcp.res == 1 || hdr.tcp.cwr == 1 ||
						hdr.tcp.ece == 1 || hdr.tcp.urg == 1 ||
						hdr.tcp.psh == 1 || hdr.tcp.rst == 1 ||
						hdr.tcp.fin == 1)
					drop();
				// connection started with B
				else if (hdr.tcp.syn == 1 && hdr.tcp.ack == 1)
					syn_ack.apply();
				// we should get a syn
				else if (hdr.tcp.syn == 1)
					handle_syn();
				// or has the communication already started?
				else if ((hdr.tcp.ack == 1) &&
						((hdr.tcp.ackNo - 1) == meta.cookie))
					handle_ack();
				else
					drop();
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
			hdr.ipv4.setInvalid();
			hdr.tcp.setInvalid();
			if (meta.update_route == 1) {
				hdr.cpu_route.setValid();
				hdr.cpu_route.macAddr = hdr.ethernet.srcAddr;
				hdr.cpu_route.ingress_port = (bit<16>)meta.ingress_port;
				hdr.ethernet.etherType = L2_LEARN_ETHER_TYPE;
				truncate((bit<32>)(14 + 8)); //ether+cpu router
			}
			else if (meta.save_pre_connection == 1) {
				hdr.cpu_connection.setValid();
				hdr.cpu_connection.srcAddr = hdr.ipv4.srcAddr;
				hdr.cpu_connection.dstAddr = hdr.ipv4.dstAddr;
				hdr.cpu_connection.srcPort = hdr.tcp.srcPort;
				hdr.cpu_connection.dstPort = hdr.tcp.dstPort;

				hdr.cpu_connection.offset = meta.offset;

				hdr.ethernet.etherType = SAVE_PRE_CONNECTION;
				truncate((bit<32>)(14 + 16)); //ether+cpu cookie
			}
			else if (meta.save_connection == 1) {
				hdr.cpu_connection.setValid();
				hdr.cpu_connection.srcAddr = hdr.ipv4.srcAddr;
				hdr.cpu_connection.dstAddr = hdr.ipv4.dstAddr;
				hdr.cpu_connection.srcPort = hdr.tcp.srcPort;
				hdr.cpu_connection.dstPort = hdr.tcp.dstPort;

				hdr.cpu_connection.offset = meta.offset + 1;

				hdr.ethernet.etherType = SAVE_CONNECTION;
				truncate((bit<32>)(14 + 16)); //ether+cpu cookie
			}
			else {
				mark_to_drop();
			}
		}
	}
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
	apply {
		update_checksum(true, {
				hdr.ipv4.version,
				hdr.ipv4.ihl,
				hdr.ipv4.dscp,
				hdr.ipv4.ecn,
				hdr.ipv4.totalLen,
				hdr.ipv4.identification,
				hdr.ipv4.flags,
				hdr.ipv4.fragOffset,
				hdr.ipv4.ttl,
				hdr.ipv4.protocol,
				hdr.ipv4.srcAddr,
				hdr.ipv4.dstAddr
				},
				hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
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

		packet.emit(hdr.cpu_route);
		packet.emit(hdr.cpu_connection);
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
