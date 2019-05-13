control compute_cookie(inout headers hdr,
		inout metadata meta) {

	action auth_cookie() {
		bit<32> auth = 0;
		auth = (bit<32>)hdr.tcp.srcPort;
		auth = (auth << 16) | (bit<32>) hdr.tcp.dstPort;
		auth = auth ^ hdr.ipv4.srcAddr;
		auth = auth ^ hdr.ipv4.dstAddr;
		auth = (auth & 0b00000001111111111111111111111111) +
			(auth & (0b11111110000000000000000000000000));
		meta.cookie = auth << 8;
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
			if (hdr.tcp_opt.window.shift_count <= 0) {
				meta.cookie = meta.cookie | 0b0000000;
			} else if (hdr.tcp_opt.window.shift_count <= 0) { // useless
				meta.cookie = meta.cookie | 0b0010000;
			} else if (hdr.tcp_opt.window.shift_count <= 1) {
				meta.cookie = meta.cookie | 0b0100000;
			} else if (hdr.tcp_opt.window.shift_count <= 2) {
				meta.cookie = meta.cookie | 0b0110000;
			} else if (hdr.tcp_opt.window.shift_count <= 4) {
				meta.cookie = meta.cookie | 0b1000000;
			} else if (hdr.tcp_opt.window.shift_count <= 6) {
				meta.cookie = meta.cookie | 0b1010000;
			} else if (hdr.tcp_opt.window.shift_count <= 7) {
				meta.cookie = meta.cookie | 0b1100000;
			} else if (hdr.tcp_opt.window.shift_count <= 8) {
				meta.cookie = meta.cookie | 0b1110000;
			}
		}

		// from freeBSD:
		// tcp_sc_msstab[] = { 216, 536, 1200, 1360, 1400, 1440, 1452, 1460 }
		if (hdr.tcp_opt.mss.isValid()) {
			if (hdr.tcp_opt.mss.value <= 216) {
				meta.cookie = meta.cookie | 0b0000000;
			} else if (hdr.tcp_opt.mss.value <= 536) {
				meta.cookie = meta.cookie | 0b0000010;
			} else if (hdr.tcp_opt.mss.value <= 1200) {
				meta.cookie = meta.cookie | 0b0000100;
			} else if (hdr.tcp_opt.mss.value <= 1360) {
				meta.cookie = meta.cookie | 0b0000110;
			} else if (hdr.tcp_opt.mss.value <= 1400) {
				meta.cookie = meta.cookie | 0b0001000;
			} else if (hdr.tcp_opt.mss.value <= 1440) {
				meta.cookie = meta.cookie | 0b0001010;
			} else if (hdr.tcp_opt.mss.value <= 1452) {
				meta.cookie = meta.cookie | 0b0001100;
			} else if (hdr.tcp_opt.mss.value <= 1460) {
				meta.cookie = meta.cookie | 0b0001110;
			}
		}

		if (hdr.tcp_opt.sack.isValid()) {
			meta.cookie = meta.cookie | 0b0000001;
		}
	}
}

control SetOptionFromCookie(inout headers hdr,
		in bit<32> cookie) {

	apply {
		bit<16> len = 0;
		bit<3> window = (bit<3>) ((cookie & 0b1110000) >> 4);
		bit<3> mss = (bit<3>) ((cookie & 0b0001110) >> 1);
		bit<1> sack = (bit<1>) ((cookie & 0b0000001));

		// from freeBSD:
		// tcp_sc_wstab[] = { 0, 0, 1, 2, 4, 6, 7, 8 };
		if (window != 0b000 && window != 0b001) {
			hdr.tcp_opt.window.setValid();
			hdr.tcp_opt.window.type = 3;
			hdr.tcp_opt.window.len = 3;
			len = len + 3;
		}
		if (window == 0b010)
			hdr.tcp_opt.window.shift_count = 1;
		else if (window == 0b011)
			hdr.tcp_opt.window.shift_count = 2;
		else if (window == 0b100)
			hdr.tcp_opt.window.shift_count = 4;
		else if (window == 0b101)
			hdr.tcp_opt.window.shift_count = 6;
		else if (window == 0b110)
			hdr.tcp_opt.window.shift_count = 6;
		else if (window == 0b111)
			hdr.tcp_opt.window.shift_count = 7;

		// from freeBSD:
		// tcp_sc_msstab[] = { 216, 536, 1200, 1360, 1400, 1440, 1452, 1460 }
		hdr.tcp_opt.mss.setValid();
		hdr.tcp_opt.mss.type = 2;
		hdr.tcp_opt.mss.len = 4;
		len = len + 4;
		if (mss == 0b000)
			hdr.tcp_opt.mss.value = 216;
		else if (mss == 0b001)
			hdr.tcp_opt.mss.value = 536;
		else if (mss == 0b010)
			hdr.tcp_opt.mss.value = 1200;
		else if (mss == 0b011)
			hdr.tcp_opt.mss.value = 1360;
		else if (mss == 0b100)
			hdr.tcp_opt.mss.value = 1400;
		else if (mss == 0b101)
			hdr.tcp_opt.mss.value = 1440;
		else if (mss == 0b110)
			hdr.tcp_opt.mss.value = 1452;
		else if (mss == 0b111)
			hdr.tcp_opt.mss.value = 1460;

		if (sack == 1) {
			hdr.tcp_opt.sack.setValid();
			hdr.tcp_opt.sack.type = 4;
			hdr.tcp_opt.sack.len = 2;
			len = len + 2;
		}

		if ((len % 4) == 1) {
			hdr.tcp_opt.padding_3.setValid();
			hdr.tcp_opt.padding_3.padding = 0; // useless
			len = len + 3;
		} else if ((len % 4) == 2) {
			hdr.tcp_opt.padding_2.setValid();
			hdr.tcp_opt.padding_2.padding = 0; // useless
			len = len + 2;
		} else if ((len % 4) == 3) {
			hdr.tcp_opt.padding_1.setValid();
			hdr.tcp_opt.padding_1.padding = 0; // useless
			len = len + 1;
		}

		hdr.ipv4.totalLen = hdr.ipv4.totalLen + len;
		hdr.tcp.dataOffset = hdr.tcp.dataOffset + ((bit<4>) (len / 4));
	}
}
