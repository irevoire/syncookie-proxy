#ifndef _HEADER_P4_
#define _HEADER_P4_

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
	macAddr_t dstAddr;   // 6
	macAddr_t srcAddr;   // 6
	bit<16>   etherType; // 2
}

header ipv4_t {
	bit<4>    version;
	bit<4>    ihl;
	bit<6>    dscp;
	bit<2>    ecn;
	bit<16>   totalLen;
	bit<16>   identification;
	bit<3>    flags;
	bit<13>   fragOffset;
	bit<8>    ttl;
	bit<8>    protocol;
	bit<16>   hdrChecksum;
	ip4Addr_t srcAddr;
	ip4Addr_t dstAddr;
}

header tcp_t{
	bit<16> srcPort;
	bit<16> dstPort;
	bit<32> seqNo;
	bit<32> ackNo; // will carry the cookie
	bit<4>  dataOffset;
	bit<4>  res;
	bit<1>  cwr;
	bit<1>  ece;
	bit<1>  urg;
	bit<1>  ack;
	bit<1>  psh;
	bit<1>  rst;
	bit<1>  syn;
	bit<1>  fin;
	bit<16> window;
	bit<16> checksum;
	bit<16> urgentPtr;
}

header cpu_route_t {
	// router
	bit<16>   ingress_port; // 2
	macAddr_t macAddr;      // 6
}

header cpu_cookie_t {
	// synCookie Proxy
	ip4Addr_t srcAddr; // 4
	ip4Addr_t dstAddr; // 4
}

struct metadata {
	bit<16> ptcl; // ipv4 protocol for computing the checksum

	bit<1>  update_route;
	bit<1>  good_cookie;

	bit<9>  ingress_port;
	bit<32> cookie;
	bit<80> connection; // two ip address (32 * 2) + the dst port (16)
}

struct headers {
	ethernet_t   ethernet;

	cpu_route_t  cpu_route;
	cpu_cookie_t cpu_cookie;

	ipv4_t       ipv4;
	tcp_t        tcp;
}

#endif /* _HEADER_P4_ */
