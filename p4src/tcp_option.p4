#include "headers.p4"

error {
	TcpOptionTooLong,
	TcpOptionBadMssSize,
	TcpOptionBadSackSize,
	TcpOptionBadWindowSclSize
}

parser tcp_option_parser(packet_in packet,
		in bit<4> dataOffset,
		in bit<8> options,
		out tcp_option_t opt) {
	bit<32> option_size = 0;

	state start {
		option_size = ((bit<32>) dataOffset) * 4; // *4 to get bytes
		option_size = option_size - 20; // to remove the size of the tcp hdr
		transition select (options) {
			0b00000010: parse_tcp_option_check_size; // SYN
			default: accept;
		}
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

		packet.advance((bit<32>)(tmp - 1) * 8); // skip the content
		transition parse_tcp_option_check_size;
	}

	state parse_tcp_option_nop {
		packet.advance(8); // skip the nop
		option_size = option_size - 1;
		transition parse_tcp_option_check_size;
	}

	state parse_tcp_option_mss {
		packet.extract(opt.mss);
		verify(opt.mss.len == 4, error.TcpOptionBadMssSize);
		option_size = option_size - 4;
		transition parse_tcp_option_check_size;
	}

	state parse_tcp_option_sack_permitted {
		packet.extract(opt.sack);
		verify(opt.sack.len == 2, error.TcpOptionBadSackSize);
		option_size = option_size - 2;
		transition parse_tcp_option_check_size;
	}

	state parse_tcp_option_window_scale {
		packet.extract(opt.window);
		verify(opt.window.len == 3, error.TcpOptionBadWindowSclSize);
		option_size = option_size - 3;
		transition parse_tcp_option_check_size;
	}

}

control IngressTcpOption(inout headers hdr,
		inout metadata meta,
		inout standard_metadata_t standard_metadata) {
	apply {
		if (!hdr.tcp_opt.mss.isValid()) {
			hdr.tcp_opt.mss.setValid();
			hdr.tcp_opt.mss.type = 2;
			hdr.tcp_opt.mss.len = 4;
		}
		if (!hdr.tcp_opt.sack.isValid()) {
			hdr.tcp_opt.sack.setValid();
			hdr.tcp_opt.sack.type = 4;
			hdr.tcp_opt.sack.len = 2;
		}
		if (!hdr.tcp_opt.window.isValid()) {
			hdr.tcp_opt.window.setValid();
			hdr.tcp_opt.window.type = 3;
			hdr.tcp_opt.window.len = 3;
		}
	}
}
