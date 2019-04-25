parser tcp_option_parser(packet_in packet,
		out headers hdr) {
	bit<32> option_size = 0;

	state start {
		option_size = ((bit<32>) hdr.tcp.dataOffset) * 4; // *4 to get bytes
		transition parse_tcp_option_check_size;
	}

	state parse_tcp_option_check_size {
		transition select (option_size) {
			0: accept;
			default: parse_tcp_option;
		}
	}

	state parse_tcp_option {
		transition select(packet.lookahead<bit<8>>()) {
			1: parse_tcp_option_nop;
			2: parse_tcp_option_mss;
			3: parse_tcp_option_window_scale;
			4: parse_tcp_option_sack_permitted;
			default: parse_tcp_unkown;
		}
	}

	state parse_tcp_unkown {
		packet.advance(8); // skip the type

		bit<8> tmp;
		tmp = packet.lookahead<bit<8>>(); // get the size in bytes
		option_size = option_size - (bit<32>) tmp;

		packet.advance((bit<32>)(tmp - 2)); // skip the content of the option
		transition parse_tcp_option_check_size;
	}

	state parse_tcp_option_nop {
		packet.advance(8);
		option_size = option_size - 1;
		transition parse_tcp_option_check_size;
	}

	state parse_tcp_option_mss {
		packet.extract(hdr.mss);
		option_size = option_size - 4;
		transition parse_tcp_option;
	}

	state parse_tcp_option_sack_permitted {
		packet.extract(hdr.sack);
		option_size = option_size - 2;
		transition parse_tcp_option;
	}

	state parse_tcp_option_window_scale {
		packet.extract(hdr.window);
		option_size = option_size - 3;
		transition parse_tcp_option;
	}

}
