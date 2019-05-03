control IngressForwarding(inout headers hdr,
		inout metadata meta,
		inout standard_metadata_t standard_metadata) {
	action drop() {
		mark_to_drop(standard_metadata);
	}

	action mac_learn() {
		meta.ingress_port = standard_metadata.ingress_port;
		meta.update_route = 1;
		clone3(CloneType.I2E, 100, meta);
	}

	table smac {
		key = {
			hdr.ethernet.srcAddr: exact;
		}

		actions = {
			mac_learn;
			NoAction;
		}
		size = 256;
		default_action = mac_learn;
	}

	action forward(bit<9> egress_port) {
		standard_metadata.egress_spec = egress_port;
	}

	table dmac {
		key = {
			hdr.ethernet.dstAddr: exact;
		}

		actions = {
			forward;
			NoAction;
		}
		size = 256;
		default_action = NoAction;
	}

	action set_mcast_grp(bit<16> mcast_grp) {
		standard_metadata.mcast_grp = mcast_grp;
	}

	table broadcast {
		key = {
			standard_metadata.ingress_port: exact;
		}

		actions = {
			set_mcast_grp;
			NoAction;
		}
		size = 256;
		default_action = NoAction;
	}

	apply {
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
		smac.apply();
		if (!dmac.apply().hit) {
			broadcast.apply();
		}
	}
}
