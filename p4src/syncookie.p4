/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control IngressSyncookie(inout headers hdr,
		inout metadata meta,
		inout standard_metadata_t standard_metadata) {
	action drop() {
		mark_to_drop(standard_metadata);
	}

	action compute_connection() {
		meta.connection = (bit<80>)hdr.ipv4.srcAddr;
		meta.connection = meta.connection << 32;
		meta.connection = meta.connection | (bit<80>)hdr.ipv4.dstAddr;
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

		// =========== TCP ============
		// first we'll update the checksum
		bit<32> checksum = ~meta.cookie; // start with the cookie to avoid overflow
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

	action handle_ack() {
		// =========== CPU ============
		meta.good_cookie = 1;
		clone3(CloneType.I2E, 100, meta);

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

		// =========== TCP ============
		bit<32> checksum = 0;
		checksum = checksum + (bit<32>) hdr.tcp.checksum;
		checksum = checksum + (bit<32>) ((hdr.tcp.seqNo & 0xFFFF0000) >> 16);
		checksum = checksum + (bit<32>) (hdr.tcp.seqNo & 0x0000FFFF);
		checksum = checksum + 0x000C; // MAGIC
		checksum = ((checksum & 0xFFFF0000) >> 16) + (checksum & 0x0000FFFF);
		checksum = ((checksum & 0xFFFF0000) >> 16) + (checksum & 0x0000FFFF);
		hdr.tcp.checksum = (bit<16>) checksum;

		hdr.tcp.seqNo = hdr.tcp.ackNo;
		hdr.tcp.ackNo = 0; // remove the ack

		hdr.tcp.ack = 0;
		hdr.tcp.rst = 1;

		// swap src / dst port
		bit<16> tcpport = hdr.tcp.srcPort;
		hdr.tcp.srcPort = hdr.tcp.dstPort;
		hdr.tcp.dstPort = tcpport;
	}

	apply {
		compute_connection();
		if (!tcp_forward.apply().hit) {
			compute_cookie();
			// you won't steal my cookie!
			// if SYN-ACK or any other flags, drop
			if (hdr.tcp.syn == 1 && hdr.tcp.ack == 1 ||
					hdr.tcp.res == 1 || hdr.tcp.cwr == 1 ||
					hdr.tcp.ece == 1 || hdr.tcp.urg == 1 ||
					hdr.tcp.psh == 1 || hdr.tcp.rst == 1 ||
					hdr.tcp.fin == 1)
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
