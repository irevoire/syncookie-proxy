/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "headers.p4"
#include "routing.p4"
#include "syncookie.p4"

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> L2_LEARN_ETHER_TYPE = 0x1234;
const bit<16> LEARN_COOKIE = 0xF00D;

/*************************************************************************
 ************************ P A R S E R  ***********************************
 *************************************************************************/

parser MyParser(packet_in packet,
		out headers hdr,
		inout metadata meta,
		inout standard_metadata_t standard_metadata) {

	state start {
		transition ethernet;
	}

	state ethernet {
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType) {
			TYPE_IPV4: ipv4;
			default: accept;
		}
	}

	state ipv4 {
		packet.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol) {
			6: parse_tcp;
			default: accept;
		}
	}

	state parse_tcp {
		packet.extract(hdr.tcp);
		transition accept;
	}
}


/*************************************************************************
 ************   C H E C K S U M    V E R I F I C A T I O N   *************
 *************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
	apply {  }
}


/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control MyIngress(inout headers hdr,
		inout metadata meta,
		inout standard_metadata_t standard_metadata) {

	apply {
		IngressForwarding.apply(hdr, meta, standard_metadata);
		if (hdr.tcp.isValid()) {
			IngressSyncookie.apply(hdr, meta, standard_metadata);
		}
	}
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control MyEgress(inout headers hdr,
		inout metadata meta,
		inout standard_metadata_t standard_metadata) {
	apply {
		// If ingress clone
		if (standard_metadata.instance_type == 1) {
			if (meta.update_route == 1) {
				hdr.ethernet.setValid();
				hdr.cpu_route.setValid();
				hdr.cpu_route.macAddr = hdr.ethernet.srcAddr;
				hdr.cpu_route.ingress_port = (bit<16>)meta.ingress_port;
				hdr.ethernet.etherType = L2_LEARN_ETHER_TYPE;
				truncate((bit<32>)(14 + 8)); //ether+cpu router
			}
			else if (meta.good_cookie == 1) {
				hdr.ethernet.setValid();
				hdr.cpu_cookie.setValid();
				hdr.cpu_cookie.srcAddr = hdr.ipv4.srcAddr;
				hdr.cpu_cookie.dstAddr = hdr.ipv4.dstAddr;
				hdr.cpu_cookie.srcPort = hdr.tcp.srcPort;
				hdr.cpu_cookie.dstPort = hdr.tcp.dstPort;

				hdr.ethernet.etherType = LEARN_COOKIE;
				truncate((bit<32>)(14 + 12)); //ether+cpu cookie
			}
			else {
				mark_to_drop(standard_metadata);
			}
		}
	}
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
	apply {
		update_checksum(true, {
				hdr.ipv4.version,
				hdr.ipv4.ihl,
				hdr.ipv4.dscp,
				hdr.ipv4.ecn,
				hdr.ipv4.totalLen,
				hdr.ipv4.identification,
				hdr.ipv4.flags,
				hdr.ipv4.fragOffset,
				hdr.ipv4.ttl,
				hdr.ipv4.protocol,
				hdr.ipv4.srcAddr,
				hdr.ipv4.dstAddr
				},
				hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
	}
}

/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
	apply {
		//parsed headers have to be added again into the packet.
		packet.emit(hdr.ethernet);

		packet.emit(hdr.cpu_route);
		packet.emit(hdr.cpu_cookie);

		packet.emit(hdr.ipv4);
		packet.emit(hdr.tcp);
	}
}

/*************************************************************************
 ***********************  S W I T C H  *******************************
 *************************************************************************/

//switch architecture
	V1Switch(
			MyParser(),
			MyVerifyChecksum(),
			MyIngress(),
			MyEgress(),
			MyComputeChecksum(),
			MyDeparser()
		) main;
