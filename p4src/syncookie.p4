const bit<32> COOKIE_AUTH = 0b00000001111111111111111111111111;

#include "cookie.p4"

control IngressSyncookie(inout headers hdr,
		inout metadata meta,
		inout standard_metadata_t standard_metadata) {

	action drop() {
		mark_to_drop(standard_metadata);
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

	action handle_syn() {
		// =========== PHY ============
		// send the packet back to the source
		standard_metadata.egress_spec = standard_metadata.ingress_port;
		standard_metadata.mcast_grp = 0; // stop doing multicast

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
		bit<32> checksum = ~meta.cookie;
		checksum = ((checksum & 0xFFFF0000) >> 16) + (checksum & 0x0000FFFF);
		checksum = checksum + (bit<32>) hdr.tcp.checksum;
		checksum = checksum + 0xFFF0; // MAGIC
		checksum = ((checksum & 0xFFFF0000) >> 16) + (checksum & 0x0000FFFF);
		checksum = ((checksum & 0xFFFF0000) >> 16) + (checksum & 0x0000FFFF);
		hdr.tcp.checksum = (bit<16>) checksum;

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
	}

	action handle_rst() {
		// we must save the connection as a safe one
		meta.good_cookie = 1;
		clone3(CloneType.I2E, 100, meta);
		drop(); // we drop the rst because we don't want anyone to get it
	}

	apply {
		compute_connection();
		if (!tcp_forward.apply().hit) {
			compute_cookie.apply(hdr, meta);
			// you won't steal my cookie!
			// if SYN-RST or any other flags, drop
			if (hdr.tcp.syn == 1 && hdr.tcp.rst == 1 ||
					hdr.tcp.res == 1 || hdr.tcp.cwr == 1 ||
					hdr.tcp.ece == 1 || hdr.tcp.urg == 1 ||
					hdr.tcp.psh == 1 || hdr.tcp.ack == 1 ||
					hdr.tcp.fin == 1)
				drop();
			// we should get a syn
			else if (hdr.tcp.syn == 1) {
				handle_syn();
			}
			// or has the communication already started?
			else if ( (hdr.tcp.rst == 1) &&
					((hdr.tcp.seqNo & COOKIE_AUTH) ==
					 (meta.cookie & COOKIE_AUTH))
				)
				handle_rst();
			else // cookie is not good
				drop();
		}
	}
}
