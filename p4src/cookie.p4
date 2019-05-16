control compute_cookie(inout headers hdr,
		inout metadata meta) {

	action auth_cookie() {
		bit<32> auth = 0;
		auth = (bit<32>)hdr.tcp.srcPort;
		auth = (auth << 16) | (bit<32>) hdr.tcp.dstPort;
		auth = auth ^ hdr.ipv4.srcAddr;
		auth = auth ^ hdr.ipv4.dstAddr;
		auth = (auth & COOKIE_AUTH) +
			(auth & (~COOKIE_AUTH));
		meta.cookie = auth << 7;
	}

	apply {
		auth_cookie();
		// don't need to store any options
	}
}
