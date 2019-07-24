# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser

        

        mod = ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY, 
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)
    def add_flow1(self, datapath, match, actions):
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser

        

        mod = ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=1, 
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)
    def add_flow2(self, datapath, match, actions):
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser

        

        mod = ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=2,
            priority=2, 
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)
    def add_flow3(self, datapath, match, actions):
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser

        

        mod = ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=1, hard_timeout=4,
            priority=3, 
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)
    def add_flow4(self, datapath, match, actions):
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser

        

        mod = ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=5,
            priority=4, 
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)
    def add_flow5(self, datapath, match, actions):
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser

        

        mod = ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=4, hard_timeout=5,
            priority=5, 
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)
    def add_flow6(self, datapath, match, actions):
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser

        

        mod = ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=3, hard_timeout=5,
            priority=ofproto.OFP_DEFAULT_PRIORITY, 
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)
    def add_flow7(self, datapath, match, actions):
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser

        

        mod = ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=2, hard_timeout=6,
            priority=7, 
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)
    def add_flow8(self, datapath, match, actions):
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser

        

        mod = ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=8, 
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)
    def add_flow9(self, datapath, match, actions):
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser

        

        mod = ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=3, hard_timeout=7,
            priority=9, 
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)
    def add_flow10(self, datapath, match, actions):
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser

        

        mod = ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=2, hard_timeout=5,
            priority=10, 
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser
	
       

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
		 # check IP Protocol and create a match for IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto
            
                # if ICMP Protocol
                if protocol == in_proto.IPPROTO_ICMP:
                    match = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_src=srcip, nw_dst=dstip, nw_proto=protocol)
		
            
                #  if TCP Protocol
                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    match = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_src=srcip, nw_dst=dstip, nw_proto=protocol, 			    tp_src=t.src_port, tp_dst=t.dst_port)
            
                #  If UDP Protocol 
                elif protocol == in_proto.IPPROTO_UDP:
                    u = pkt.get_protocol(udp.udp)
                    match = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_src=srcip, nw_dst=dstip, nw_proto=protocol,      	             tp_src=u.src_port, tp_dst=u.dst_port)
	
            else:
                match = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=dst, dl_src=src)
            self.add_flow(datapath, match, actions)
            match5 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst, nw_proto=in_proto.IPPROTO_TCP)
            match6 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst)
            match7 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst,nw_proto=in_proto.IPPROTO_TCP)
            match8 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst,)
            match9 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst, nw_proto=in_proto.IPPROTO_ICMP)
            match10 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst, nw_proto=in_proto.IPPROTO_TCP)
            match11 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst,)
            match12 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst)
            match13 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst,nw_proto=in_proto.IPPROTO_ICMP)
            match14 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst,                 			)
            match15 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst,nw_proto=in_proto.IPPROTO_TCP)
            match16 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst)
            match17 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst, nw_proto=in_proto.IPPROTO_TCP)
            match18 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst,nw_proto=in_proto.IPPROTO_ICMP)
            match19 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst)
            match20 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst, nw_proto=in_proto.IPPROTO_TCP)
            match21 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst, )
            match22 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst, nw_proto=in_proto.IPPROTO_TCP)
            match23 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst,nw_proto=in_proto.IPPROTO_ICMP)
            match24 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst)
            match25 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst, )
            match26 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst)
            match27 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst)
            match28 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst, )
            match29 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst)
            match30 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst, nw_proto=in_proto.IPPROTO_TCP)
            match31 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst,nw_proto=in_proto.IPPROTO_TCP)
            match32 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst, )
            match33 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst,nw_proto=in_proto.IPPROTO_ICMP)
            match34 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst, nw_proto=in_proto.IPPROTO_ICMP)
            match35 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst, )
            match36 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst, nw_proto=in_proto.IPPROTO_TCP)
            match37 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst, nw_proto=in_proto.IPPROTO_ICMP)
            match38 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst,)
            match39 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst, nw_proto=in_proto.IPPROTO_TCP)
            match40 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst, nw_proto=in_proto.IPPROTO_ICMP)
            match41 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst)
            match42 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst, nw_proto=in_proto.IPPROTO_ICMP)
            match43 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst,)
            match44 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst, nw_proto=in_proto.IPPROTO_TCP)
            match45 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst, nw_proto=in_proto.IPPROTO_ICMP)
            match46 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst, )
            match47 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst,nw_proto=in_proto.IPPROTO_TCP)
            match48 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst,)
            match49 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst,)
            match50 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst,)
            match51 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst,)
            match52 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst, nw_proto=in_proto.IPPROTO_TCP)
            match53 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst,)
            match54 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst,nw_proto=in_proto.IPPROTO_ICMP)
            match55 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst,)
            match56 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst,nw_proto=in_proto.IPPROTO_TCP)
            match57 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst,)
            match58 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst, nw_proto=in_proto.IPPROTO_ICMP)
            match59 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst,)
            match60 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst,)
            match61 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst)
            match62 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst, nw_proto=in_proto.IPPROTO_TCP)
            match63 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst, )
            match64 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst, nw_proto=in_proto.IPPROTO_ICMP)
            match65 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst,nw_proto=in_proto.IPPROTO_TCP)
            match66 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst, nw_proto=in_proto.IPPROTO_ICMP)
            match67 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst, )
            match68 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst,)
            match69 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst, )
            match70 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst, )
            match71 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst,)
            match72 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst, nw_proto=in_proto.IPPROTO_TCP)
            match73 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst, nw_proto=in_proto.IPPROTO_TCP)
            match74 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst, nw_proto=in_proto.IPPROTO_ICMP)
            match75 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst,)
            match76 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst,)
            match77 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst,)
            match78 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst,)
            match79 = ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, dl_src=src, dl_dst=dst, nw_proto=in_proto.IPPROTO_TCP)
            match80 = ofproto_parser.OFPMatch(in_port=msg.in_port, dl_src=src, dl_dst=dst,nw_proto=in_proto.IPPROTO_TCP)
            
            
            self.add_flow1(datapath, match5, actions)
            self.add_flow2(datapath, match6, actions)
            self.add_flow3(datapath, match7, actions)
            self.add_flow4(datapath, match8, actions)
            self.add_flow5(datapath, match9, actions)
            self.add_flow6(datapath, match10, actions)
            self.add_flow7(datapath, match11, actions)
            self.add_flow8(datapath, match12, actions)
            self.add_flow9(datapath, match13, actions)
            self.add_flow10(datapath, match14, actions)
            self.add_flow1(datapath, match15, actions)
            self.add_flow2(datapath, match16, actions)
            self.add_flow3(datapath, match17, actions)
            self.add_flow4(datapath, match18, actions)
            self.add_flow5(datapath, match19, actions)
            self.add_flow6(datapath, match20, actions)
            self.add_flow7(datapath, match21, actions)
            self.add_flow8(datapath, match22, actions)
            self.add_flow9(datapath, match23, actions)
            self.add_flow10(datapath, match24, actions)
            self.add_flow1(datapath, match25, actions)
            self.add_flow2(datapath, match26, actions)
            self.add_flow3(datapath, match27, actions)
            self.add_flow4(datapath, match28, actions)
            self.add_flow5(datapath, match29, actions)
            self.add_flow6(datapath, match30, actions)
            self.add_flow7(datapath, match31, actions)
            self.add_flow8(datapath, match32, actions)
            self.add_flow9(datapath, match33, actions)
            self.add_flow10(datapath, match34, actions)
            self.add_flow1(datapath, match35, actions)
            self.add_flow2(datapath, match36, actions)
            self.add_flow3(datapath, match37, actions)
            self.add_flow4(datapath, match38, actions)
            self.add_flow5(datapath, match39, actions)
            self.add_flow6(datapath, match40, actions)
            self.add_flow7(datapath, match41, actions)
            self.add_flow8(datapath, match42, actions)
            self.add_flow9(datapath, match43, actions)
            self.add_flow10(datapath, match44, actions)
            self.add_flow1(datapath, match45, actions)
            self.add_flow2(datapath, match46, actions)
            self.add_flow3(datapath, match47, actions)
            self.add_flow4(datapath, match48, actions)
            self.add_flow5(datapath, match49, actions)
            self.add_flow6(datapath, match50, actions)
            self.add_flow7(datapath, match51, actions)
            self.add_flow8(datapath, match52, actions)
            self.add_flow9(datapath, match53, actions)
            self.add_flow10(datapath, match54, actions)
            self.add_flow1(datapath, match55, actions)
            self.add_flow2(datapath, match56, actions)
            self.add_flow3(datapath, match57, actions)
            self.add_flow4(datapath, match58, actions)
            self.add_flow5(datapath, match59, actions)
            self.add_flow6(datapath, match60, actions)
            self.add_flow7(datapath, match61, actions)
            self.add_flow8(datapath, match62, actions)
            self.add_flow9(datapath, match63, actions)
            self.add_flow10(datapath, match64, actions)
            self.add_flow1(datapath, match65, actions)
            self.add_flow2(datapath, match66, actions)
            self.add_flow3(datapath, match67, actions)
            self.add_flow4(datapath, match68, actions)
            self.add_flow5(datapath, match69, actions)
            self.add_flow6(datapath, match70, actions)
            self.add_flow7(datapath, match71, actions)
            self.add_flow8(datapath, match72, actions)
            self.add_flow9(datapath, match73, actions)
            self.add_flow10(datapath, match74, actions)
            self.add_flow1(datapath, match75, actions)
            self.add_flow2(datapath, match76, actions)
            self.add_flow3(datapath, match77, actions)
            self.add_flow4(datapath, match78, actions)
            self.add_flow5(datapath, match79, actions)
            self.add_flow6(datapath, match80, actions)
            

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
