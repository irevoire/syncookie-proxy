const bit<32> COOKIE_AUTH = 0b00000001111111111111111111111111;

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

	action compute_cookie() {
		bit<32> auth_cookie = 0;
		auth_cookie = (bit<32>)hdr.tcp.srcPort;
		auth_cookie = (auth_cookie << 16) | (bit<32>) hdr.tcp.dstPort;
		auth_cookie = auth_cookie ^ hdr.ipv4.srcAddr;
		auth_cookie = auth_cookie ^ hdr.ipv4.dstAddr;
		auth_cookie = (auth_cookie & COOKIE_AUTH) +
			(auth_cookie & (~COOKIE_AUTH));
		meta.cookie = auth_cookie << 7;

		// TODO add the other field in the cookie
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
		// send some a bad sequence number
		hdr.tcp.seqNo = hdr.tcp.seqNo - 1;
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
		drop(); // we drop the rst because we don't want anyone to get it
	}

	apply {
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
			else if (hdr.tcp.syn == 1) {
				IngressTcpOption.apply(hdr, meta, standard_metadata);
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
