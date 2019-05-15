control ComputeTcpChecksum(inout headers hdr) {
	apply {
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
		if (hdr.tcp_opt.mss.isValid()) {
			tmp = 0;
			tmp = tmp | ((bit<16>) hdr.tcp_opt.mss.type) << 8;
			tmp = tmp | ((bit<16>) hdr.tcp_opt.mss.len);
			checksum = checksum + (bit<32>) tmp;
			checksum = checksum + (bit<32>) hdr.tcp_opt.mss.value;
		}
		// sack permitted
		if (hdr.tcp_opt.sack.isValid()) {
			tmp = 0;
			tmp = tmp | ((bit<16>) hdr.tcp_opt.sack.type) << 8;
			tmp = tmp | ((bit<16>) hdr.tcp_opt.sack.len);
			checksum = checksum + (bit<32>) tmp;
		}
		// window scale
		if (hdr.tcp_opt.window.isValid()) {
			tmp = 0;
			tmp = tmp | ((bit<16>) hdr.tcp_opt.window.type) << 8;
			tmp = tmp | ((bit<16>) hdr.tcp_opt.window.len);
			checksum = checksum + (bit<32>) tmp;

			tmp = 0;
			tmp = tmp | ((bit<16>) hdr.tcp_opt.window.shift_count) << 8;
			checksum = checksum + (bit<32>) tmp;
		}
		// no need to handle the padding since it's always 0's

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
}

