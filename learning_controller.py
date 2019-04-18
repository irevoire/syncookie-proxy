import nnpy
import struct
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField

def p(n):
    if n <= 0:
        return ""
    return p(n >> 8) + chr(n & 0xff)

class CpuRoute(Packet):
    name = 'CpuPacket'
    fields_desc = [
            # router
            BitField('ingress_port', 0, 16),
            BitField('macAddr',0,48),
            ]

class CpuCookie(Packet):
    name = 'CpuPacket'
    fields_desc = [
            # synCookie Proxy
            BitField('srcAddr', 0, 32),
            BitField('dstAddr', 0, 32),
            BitField('srcPort', 0, 16),
            BitField('dstPort', 0, 16),

            BitField('offset', 0, 32),
            ]

class L2Controller(object):
    def __init__(self, sw_name):
        self.topo = Topology(db="topology.db")
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.cpu_port =  self.topo.get_cpu_port_index(self.sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)

        self.init()

    def init(self):
        self.controller.reset_state()
        self.add_boadcast_groups()
        self.add_mirror()

    def add_mirror(self):
        if self.cpu_port:
            self.controller.mirroring_add(100, self.cpu_port)

    def add_boadcast_groups(self):
        interfaces_to_port = self.topo[self.sw_name]["interfaces_to_port"].copy()
        # filter lo and cpu port
        interfaces_to_port.pop('lo', None)
        interfaces_to_port.pop(self.topo.get_cpu_port_intf(self.sw_name), None)

        mc_grp_id = 1
        rid = 0
        for ingress_port in interfaces_to_port.values():

            port_list = interfaces_to_port.values()[:]
            del(port_list[port_list.index(ingress_port)])

            #add multicast group
            self.controller.mc_mgrp_create(mc_grp_id)

            #add multicast node group
            handle = self.controller.mc_node_create(rid, port_list)

            #associate with mc grp
            self.controller.mc_node_associate(mc_grp_id, handle)

            #fill broadcast table
            self.controller.table_add("broadcast", "set_mcast_grp", [str(ingress_port)], [str(mc_grp_id)])

            mc_grp_id +=1
            rid +=1

    def learn_route(self, learning_data):
        for mac_addr, ingress_port in  learning_data:
            print "mac: %012X ingress_port: %s " % (mac_addr, ingress_port)
            self.controller.table_add("smac", "NoAction", [str(mac_addr)])
            self.controller.table_add("dmac", "forward", [str(mac_addr)], [str(ingress_port)])

    def save_pre_connection(self, srcA, dstA, srcP, dstP, offset):
        # we save the connection in reverse because we know it's B who's gonna answer
        connection = dstA
        connection = connection << 32
        connection = connection | srcA
        connection = connection << 16
        connection = connection | dstP
        connection = connection << 16
        connection = connection | srcP
        self.controller.table_add("syn_ack", "handle_syn_ack",
                [str(connection)], [str(offset)])

    def save_connection(self, srcA, dstA, srcP, dstP, offset):
        connection = srcA
        connection = connection << 32
        connection = connection | dstA
        connection = connection << 16
        connection = connection | srcP
        connection = connection << 16
        connection = connection | dstP
        self.controller.table_add("tcp_forward", "update_seqNo",
                [str(connection)], [str(offset)])

        connection = dstA
        connection = connection << 32
        connection = connection | srcA
        connection = connection << 16
        connection = connection | dstP
        connection = connection << 16
        connection = connection | srcP
        self.controller.table_add("tcp_forward", "update_ackNo",
                [str(connection)], [str(offset)])

    def recv_msg_cpu(self, pkt):
        packet = Ether(str(pkt))

        if packet.type == 0x1234:
            learning = CpuRoute(packet.payload)
            self.learn_route([(learning.macAddr, learning.ingress_port)])
        elif packet.type == 0xF00D: # pre connection
            learning = CpuCookie(packet.payload)
            self.save_pre_connection(learning.srcAddr, learning.dstAddr, learning.srcPort, learning.dstPort, learning.offset)
        elif packet.type == 0xCACA: # pre connection
            learning = CpuCookie(packet.payload)
            self.save_connection(learning.srcAddr, learning.dstAddr, learning.srcPort, learning.dstPort, learning.offset)

    def run_cpu_port_loop(self):
        cpu_port_intf = str(self.topo.get_cpu_port_intf(self.sw_name).replace("eth0", "eth1"))
        sniff(iface=cpu_port_intf, prn=self.recv_msg_cpu)

if __name__ == "__main__":
    import sys
    sw_name = sys.argv[1]
    controller = L2Controller(sw_name).run_cpu_port_loop()

