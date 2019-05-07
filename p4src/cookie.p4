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

	// * Schematic construction of a syncookie enabled Initial Sequence Number:
	// *  0        1         2         3
	// *  12345678901234567890123456789012
	// * |xxxxxxxxxxxxxxxxxxxxxxxxWWWMMMSP|
	// *
	// *  x 24 MAC (truncated)
	// *  W  3 Send Window Scale index
	// *  M  3 MSS index
	// *  S  1 SACK permitted
	apply {
		auth_cookie();

		// from freeBSD:
		// tcp_sc_wstab[] = { 0, 0, 1, 2, 4, 6, 7, 8 };
		if (hdr.tcp_opt.window.isValid()) {
			if (hdr.tcp_opt.window.shift_count >= 0) {
				meta.cookie = meta.cookie | 0b0000000;
			} else if (hdr.tcp_opt.window.shift_count >= 0) { // useless
				meta.cookie = meta.cookie | 0b0010000;
			} else if (hdr.tcp_opt.window.shift_count >= 1) {
				meta.cookie = meta.cookie | 0b0100000;
			} else if (hdr.tcp_opt.window.shift_count >= 2) {
				meta.cookie = meta.cookie | 0b0110000;
			} else if (hdr.tcp_opt.window.shift_count >= 4) {
				meta.cookie = meta.cookie | 0b1000000;
			} else if (hdr.tcp_opt.window.shift_count >= 6) {
				meta.cookie = meta.cookie | 0b1010000;
			} else if (hdr.tcp_opt.window.shift_count >= 7) {
				meta.cookie = meta.cookie | 0b1100000;
			} else if (hdr.tcp_opt.window.shift_count >= 8) {
				meta.cookie = meta.cookie | 0b1110000;
			}
		}

		// from freeBSD:
		// tcp_sc_msstab[] = { 216, 536, 1200, 1360, 1400, 1440, 1452, 1460 }
		if (hdr.tcp_opt.mss.isValid()) {
			if (hdr.tcp_opt.mss.value >= 216) {
				meta.cookie = meta.cookie | 0b0000000;
			} else if (hdr.tcp_opt.mss.value >= 536) {
				meta.cookie = meta.cookie | 0b0000010;
			} else if (hdr.tcp_opt.mss.value >= 1200) {
				meta.cookie = meta.cookie | 0b0000100;
			} else if (hdr.tcp_opt.mss.value >= 1360) {
				meta.cookie = meta.cookie | 0b0000110;
			} else if (hdr.tcp_opt.mss.value >= 1400) {
				meta.cookie = meta.cookie | 0b0001000;
			} else if (hdr.tcp_opt.mss.value >= 1440) {
				meta.cookie = meta.cookie | 0b0001010;
			} else if (hdr.tcp_opt.mss.value >= 1452) {
				meta.cookie = meta.cookie | 0b0001100;
			} else if (hdr.tcp_opt.mss.value >= 1460) {
				meta.cookie = meta.cookie | 0b0001110;
			}
		}

		if (hdr.tcp_opt.sack.isValid()) {
			meta.cookie = meta.cookie | 0b0000001;
		}
	}
}
