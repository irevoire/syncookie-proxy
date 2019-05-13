const bit<32> COOKIE_AUTH = 0b11111111111111111111111110000000;

#include "cookie.p4"
#include "checksum.p4"

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

		// TCP Option
		hdr.tcp.dataOffset = 0b1000;
		hdr.tcp_opt.padding_3.setValid();
		hdr.tcp_opt.padding_3.padding = 0; // should be useless
		hdr.ipv4.totalLen = 52;
		meta.ptcl = (bit<16>) hdr.ipv4.protocol;
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
		compute_connection();
		if (!tcp_forward.apply().hit) {
			compute_cookie.apply(hdr, meta);
			// you won't steal my cookie!
			if (hdr.tcp.res == 1 || hdr.tcp.cwr == 1 ||
					hdr.tcp.ece == 1 || hdr.tcp.urg == 1 ||
					hdr.tcp.psh == 1 || hdr.tcp.rst == 1 ||
					hdr.tcp.fin == 1)
				drop();
			// connection started with B
			else if (hdr.tcp.syn == 1 && hdr.tcp.ack == 1)
				syn_ack.apply();
			// we should get a syn
			else if (hdr.tcp.syn == 1) {
				TcpOptionInit.apply(hdr, meta, standard_metadata);
				handle_syn();
			}
			// or has the communication already started?
			else if ( (hdr.tcp.ack == 1) &&
					(((hdr.tcp.ackNo - 1) & COOKIE_AUTH) ==
					 (meta.cookie & COOKIE_AUTH) )
				) {
				// we use the ackNo on the next line because we want the
				// original cookie with information about the mss and sack
				SetOptionFromCookie.apply(hdr, (hdr.tcp.ackNo - 1));
				handle_ack();
			}
			else // impossible
				drop();
			ComputeTcpChecksum.apply(hdr);
		}
	}
}
