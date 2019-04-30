/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "headers.p4"
#include "tcp_option_parser.p4"

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> L2_LEARN_ETHER_TYPE = 0x1234;
const bit<16> LEARN_COOKIE = 0xF00D;

/*************************************************************************
 ************************* E R R O R  ************************************
 *************************************************************************/


/*************************************************************************
 ************************ P A R S E R  ***********************************
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
		tcp_option_parser.apply(packet, hdr.tcp.dataOffset, hdr.tcp_opt);
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
		mark_to_drop(standard_metadata);
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

	table tcp_forward {
		key = {
			meta.connection: exact;
		}
		actions = {
			NoAction;
		}
		size = 256;
		default_action = NoAction;
	}

	action compute_tcp_checksum() {
		bit<32> checksum = 0;

		// === TCP HEADER ===
		checksum = checksum + (bit<32>) hdr.tcp.srcPort;
		checksum = checksum + (bit<32>) hdr.tcp.dstPort;
		checksum = checksum + (bit<32>) (hdr.tcp.seqNo & 0x0000FFFF);
		checksum = checksum + (bit<32>) ((hdr.tcp.seqNo & 0xFFFF0000) >> 16);

		checksum = checksum + (bit<32>) (hdr.tcp.ackNo & 0x0000FFFF);
		checksum = checksum + (bit<32>) ((hdr.tcp.ackNo & 0xFFFF0000) >> 16);
		// tcp dataOffset + all the flags
		bit<16> tmp = 0;
		tmp = tmp | ((bit<16>) hdr.tcp.dataOffset) << 12;
		tmp = tmp | ((bit<16>) hdr.tcp.res) << 8;
		tmp = tmp | ((bit<16>) hdr.tcp.cwr) << 7;
		tmp = tmp | ((bit<16>) hdr.tcp.ece) << 6;
		tmp = tmp | ((bit<16>) hdr.tcp.urg) << 5;
		tmp = tmp | ((bit<16>) hdr.tcp.ack) << 4;
		tmp = tmp | ((bit<16>) hdr.tcp.psh) << 3;
		tmp = tmp | ((bit<16>) hdr.tcp.rst) << 2;
		tmp = tmp | ((bit<16>) hdr.tcp.syn) << 1;
		tmp = tmp | ((bit<16>) hdr.tcp.fin) << 0;

		checksum = checksum + (bit<32>) tmp;
		checksum = checksum + (bit<32>) hdr.tcp.window;
		checksum = checksum + (bit<32>) hdr.tcp.urgentPtr;

		// === TCP OPTIONS ===
		// mss
		tmp = 0;
		tmp = tmp | ((bit<16>) hdr.tcp_opt.mss.type) << 8;
		tmp = tmp | ((bit<16>) hdr.tcp_opt.mss.len);
		checksum = checksum + (bit<32>) tmp;
		checksum = checksum + (bit<32>) hdr.tcp_opt.mss.value;
		// sack permitted
		tmp = 0;
		tmp = tmp | ((bit<16>) hdr.tcp_opt.sack.type) << 8;
		tmp = tmp | ((bit<16>) hdr.tcp_opt.sack.len);
		checksum = checksum + (bit<32>) tmp;
		// sack window scale
		tmp = 0;
		tmp = tmp | ((bit<16>) hdr.tcp_opt.window.type) << 8;
		tmp = tmp | ((bit<16>) hdr.tcp_opt.window.len);
		checksum = checksum + (bit<32>) tmp;

		tmp = 0;
		tmp = tmp | ((bit<16>) hdr.tcp_opt.window.shift_count) << 8;
		checksum = checksum + (bit<32>) tmp;

		// === TCP PSEUDO HEADER ===
		checksum = checksum + (bit<32>) (hdr.ipv4.srcAddr & 0x0000FFFF);
		checksum = checksum + (bit<32>) ((hdr.ipv4.srcAddr >> 16) & 0x0000FFFF);
		checksum = checksum + (bit<32>) (hdr.ipv4.dstAddr & 0x0000FFFF);
		checksum = checksum + (bit<32>) ((hdr.ipv4.dstAddr >> 16) & 0x0000FFFF);
		// zero + protocol number
		tmp = 0;
		tmp = tmp | (bit<16>) hdr.ipv4.protocol;
		checksum = checksum + (bit<32>) tmp;
		// tcp length
		tmp = 0;
		tmp = tmp | (bit<16>) hdr.tcp.dataOffset;
		tmp = tmp * 4;
		checksum = checksum + (bit<32>) tmp;

		checksum = ((checksum & 0xFFFF0000) >> 16) + (checksum & 0x0000FFFF);
		checksum = ((checksum & 0xFFFF0000) >> 16) + (checksum & 0x0000FFFF);
		hdr.tcp.checksum = ~((bit<16>) checksum);
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

		// =========== TCP ============
		// send some a bad sequence number
		hdr.tcp.seqNo = hdr.tcp.seqNo - 1; // !!! magic was calculated with this number
		// put the cookie in the ackNo to force the client to send a RST
		hdr.tcp.ackNo = meta.cookie;
		// set the tcp flags to SYN-ACK
		hdr.tcp.ack = 1;

		// swap src / dst port
		bit<16> tcpport = hdr.tcp.srcPort;
		hdr.tcp.srcPort = hdr.tcp.dstPort;
		hdr.tcp.dstPort = tcpport;

		// TCP Option
		hdr.tcp.dataOffset = 0b1000;
		hdr.tcp_opt.padding.setValid();
		hdr.tcp_opt.padding.padding = 0; // should be useless
		hdr.ipv4.totalLen = 52;
		meta.ptcl = (bit<16>) hdr.ipv4.protocol;


		compute_tcp_checksum();
	}

	action handle_rst() {
		// we must save the connection as a safe one
		meta.good_cookie = 1;
		clone3(CloneType.I2E, 100, meta);
		drop();
		// we do nothing else because we expect the sender to start a new connection
	}

	apply {
		smac.apply();
		if (!dmac.apply().hit) {
			broadcast.apply();
		}
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
		if (hdr.tcp.isValid()) {
			compute_connection();
			if (!tcp_forward.apply().hit) {
				compute_cookie();
				// you won't steal my cookie!
				// if SYN-RST or any other flags, drop
				if (hdr.tcp.syn == 1 && hdr.tcp.rst == 1 ||
						hdr.tcp.res == 1 || hdr.tcp.cwr == 1 ||
						hdr.tcp.ece == 1 || hdr.tcp.urg == 1 ||
						hdr.tcp.psh == 1 || hdr.tcp.ack == 1 ||
						hdr.tcp.fin == 1)
					drop();
				// we should get a syn
				else if (hdr.tcp.syn == 1)
					handle_syn();
				// or has the communication already started?
				else if ( (hdr.tcp.rst == 1) &&
						(hdr.tcp.seqNo == meta.cookie) )
					handle_rst();
				else // cookie is not good
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
			if (meta.update_route == 1) {
				hdr.ethernet.setValid();
				hdr.cpu_route.setValid();
				hdr.cpu_route.macAddr = hdr.ethernet.srcAddr;
				hdr.cpu_route.ingress_port = (bit<16>)meta.ingress_port;
				hdr.ethernet.etherType = L2_LEARN_ETHER_TYPE;
				truncate((bit<32>)(14 + 8)); //ether+cpu router
			}
			else if (meta.good_cookie == 1) {
				hdr.ethernet.setValid();
				hdr.cpu_cookie.setValid();
				hdr.cpu_cookie.srcAddr = hdr.ipv4.srcAddr;
				hdr.cpu_cookie.dstAddr = hdr.ipv4.dstAddr;
				hdr.cpu_cookie.srcPort = hdr.tcp.srcPort;
				hdr.cpu_cookie.dstPort = hdr.tcp.dstPort;

				hdr.ethernet.etherType = LEARN_COOKIE;
				truncate((bit<32>)(14 + 12)); //ether+cpu cookie
			}
			else {
				mark_to_drop(standard_metadata);
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
		packet.emit(hdr.tcp_opt);

		packet.emit(hdr.cpu_route);
		packet.emit(hdr.cpu_cookie);
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
