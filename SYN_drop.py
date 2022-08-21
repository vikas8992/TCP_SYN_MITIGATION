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

from curses.ascii import FS
from operator import add
from defer import return_value
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
import time
class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}
        self.ip_list={}
        self.datapaths=[]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        if datapath not in self.datapaths:
            self.datapaths.append(datapath)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions,0,0)
    
    def add_flow(self, datapath, priority, match, actions,idle,hard,buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,idle_timeout=idle, hard_timeout=hard,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,idle_timeout=idle, hard_timeout=hard,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
    
    def add_flows(self,switches,priority, match, actions,idle,hard,dst,buffer_id=None):
        for datapath in switches:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            if len(actions)!=0:
                out_mac = self.ip_to_mac[dst]
            
                if out_mac in self.mac_to_port[datapath.id]:
                    out_port = self.mac_to_port[datapath.id][out_mac]
                else:
                    out_port = ofproto.OFPP_FLOOD
            
                actions = [parser.OFPActionOutput(out_port)]
    
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
            if buffer_id:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,idle_timeout=idle, hard_timeout=hard,
                                    priority=priority, match=match,
                                    instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,idle_timeout=idle, hard_timeout=hard,
                                    match=match, instructions=inst)
            datapath.send_msg(mod)
        
        
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)      
        
        # learn a mac address to avoid FLOOD next time.
        
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]

        
        # check if current packet will be dropped or not
        drop_current_packet=False
        # set idel and hard time out
        idle=0
        hard=0
        # install a flow to avoid packet_in next time
        tcp_handler_return_value=0
        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
                dst_ip=pkt_ipv4.dst
                src_ip=pkt_ipv4.src 
                if dst_ip not in self.ip_to_mac:
                    self.ip_to_mac[dst_ip]=dst
                if src_ip not in self.ip_to_mac:
                    self.ip_to_mac[src_ip]=src 
                if pkt_ipv4.proto==6:  
                    pkt_tcp = pkt.get_protocol(tcp.tcp)
                    tcp_handler_return_value=self._tcp_traffic_handler(pkt_ipv4, pkt_tcp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst, ip_proto=pkt_ipv4.proto)
                    
                    if tcp_handler_return_value==2:
                        actions=[]
                        drop_current_packet=True
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=pkt_ipv4.src)
                        idle=60  
                        hard=60
                    elif tcp_handler_return_value==3:
                        return
                    elif tcp_handler_return_value==4:
                        pass
                    elif tcp_handler_return_value==1:
                        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst, ip_proto=pkt_ipv4.proto, tcp_flags=2)
                    else:
                        drop_current_packet=False
                #ICMP Packet
                elif pkt_ipv4.proto==1:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst, ip_proto=pkt_ipv4.proto)
            
                #ICMP Packet 
                elif pkt_ipv4.proto==17:
                    pkt_udp = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst, ip_proto=pkt_ipv4.proto, udp_src=pkt_udp.src_port, udp_dst=pkt_udp.dst_port)
                else:
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
                if tcp_handler_return_value==2 or tcp_handler_return_value==1:
                    if tcp_handler_return_value==2:
                        priority=1111
                    else:
                        priority=1000
                    self.add_flow(datapath, priority, match, actions,idle,hard)
                elif tcp_handler_return_value==4:
                    pass
                else:
                    
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 100, match, actions,idle,hard, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match, actions,idle,hard)
                
          
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        if drop_current_packet:
            actions=[]
        if tcp_handler_return_value==1 or tcp_handler_return_value==4:
            actions = [parser.OFPActionOutput(out_port)]
        # what to do with current packet
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
  
   # TCP traffic handle function
            
        
    def _tcp_traffic_handler(self, pkt_ipv4, pkt_tcp):
        allowed_packet=12
        # SYN packet:
        if(pkt_tcp.bits==2):
            # If its a first SYN packet from an IP
            if(pkt_ipv4.src not in self.ip_list):
                timestamp=int(time.time())
                self.ip_list[pkt_ipv4.src]=[1,timestamp]
                return 3
            # If its a second packet from an IP    
            elif(pkt_ipv4.src in self.ip_list and self.ip_list[pkt_ipv4.src][0]==1):
                
                timestamp=int(time.time())
                if(timestamp-self.ip_list[pkt_ipv4.src][1]>60):
                    self.ip_list[pkt_ipv4.src]=[1,timestamp]
                else:
                    self.ip_list[pkt_ipv4.src][0]=self.ip_list[pkt_ipv4.src][0]+1
                return 1
            # If SYN packet number is more than allowed packets
            elif(pkt_ipv4.src in self.ip_list and self.ip_list[pkt_ipv4.src][0]>=allowed_packet):
                self.ip_list.pop(pkt_ipv4.src)
                return 2
                
            else:
                timestamp=int(time.time())
                if(timestamp-self.ip_list[pkt_ipv4.src][1]>60):
                    self.ip_list[pkt_ipv4.src]=[1,timestamp]
                else:
                    self.ip_list[pkt_ipv4.src][0]=self.ip_list[pkt_ipv4.src][0]+1
                return 4
        else:
            return 5           
            
        
    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        action = [parser.OFPActionOutput(port=port)]
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        out = parser.OFPPacketOut(datapath=datapath,buffer_id=ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER,actions=action,data=data)
        datapath.send_msg(out)