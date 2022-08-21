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
import random
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
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
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
 # modified code
 # add_flows function is added to install flow on every switch connected to the controller   
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
        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                # added code
                pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
                dst_ip=pkt_ipv4.dst
                src_ip=pkt_ipv4.src 
                if dst_ip not in self.ip_to_mac:
                    self.ip_to_mac[dst_ip]=dst
                if src_ip not in self.ip_to_mac:
                    self.ip_to_mac[src_ip]=src
                tcp_handler_return_value=False 
                if pkt_ipv4.proto==6:  
                    pkt_tcp = pkt.get_protocol(tcp.tcp)
                    tcp_handler_return_value=self._tcp_traffic_handler(datapath, in_port,eth, pkt_ipv4, pkt_tcp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst, ip_proto=pkt_ipv4.proto)
                    
                    if tcp_handler_return_value==2:
                        # flow rule will be added for 15 seconds
                        idle=60  
                        hard=60
                        drop_current_packet=True
                        
                    elif tcp_handler_return_value==3:
                        # Drop action for the malicous IP for all type of traffic
                        actions=[]
                        drop_current_packet=True
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=pkt_ipv4.src) 
                        
                    elif tcp_handler_return_value==4:
                        # Do nothing 
                        return
                    else:
                        idle=15  
                        hard=15
                        drop_current_packet=False
                #ICMP Packet
                elif pkt_ipv4.proto==1:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst, ip_proto=pkt_ipv4.proto)
            
                #UDP Packet 
                elif pkt_ipv4.proto==17:
                    pkt_udp = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst, ip_proto=pkt_ipv4.proto, udp_src=pkt_udp.src_port, udp_dst=pkt_udp.dst_port)
                else:
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
                if tcp_handler_return_value==2 or tcp_handler_return_value==3:
                    #If IP is verified then add flows on all connected switches to avoid varify again
                    self.add_flows(self.datapaths, 100, match, actions,idle,hard,pkt_ipv4.dst)
                else:
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 100, match, actions,idle,hard, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 100, match, actions,idle,hard)
                
          
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        if drop_current_packet:
            actions=[]
        # what to do with current packet
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
            
  # TCP traffic handle function
  #       
    def _tcp_traffic_handler(self, datapath, in_port,pkt_ethernet, pkt_ipv4, pkt_tcp):
        s_port= pkt_tcp.src_port
        d_port= pkt_tcp.dst_port
        # SYN packet:
        
        
        
        timestamp=int(time.time())
        remove_ip=[]
        for i in self.ip_list:
            if(timestamp-self.ip_list[i][3]>60):
                remove_ip.append(i)
        for i in remove_ip:
            self.ip_list.pop(i) 
        
        
        # SYN packet:
        if(pkt_tcp.bits==2):
            if(pkt_ipv4.src in self.ip_list and self.ip_list[pkt_ipv4.src][2]=="IN_PROCESS"):
                return 3
            else:
                # Generate random sequence number
                s_seq_no=random.randrange(120000000,999999999)
                r_seq_no=pkt_tcp.seq
                s_ack_no=r_seq_no+1
                pkt = packet.Packet()
                pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,dst=pkt_ethernet.src,src=pkt_ethernet.dst))
                pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,src=pkt_ipv4.dst,proto=pkt_ipv4.proto))
                self.ip_list[pkt_ipv4.src]=[s_seq_no,pkt_tcp.seq+1,"IN_PROCESS",timestamp]
                pkt.add_protocol(tcp.tcp(src_port=d_port,dst_port=s_port,seq=s_seq_no,ack=s_ack_no, bits=18))
                self._send_packet(datapath, in_port, pkt)
                return 4
        # ACK packet:
        elif(pkt_tcp.bits==16):
            if(pkt_ipv4.src in self.ip_list):
                temp_list=self.ip_list[pkt_ipv4.src]
                if(temp_list[2]=="IN_PROCESS" and temp_list[0]==pkt_tcp.ack-1 and temp_list[1]==pkt_tcp.seq):
                    self.ip_list.pop(pkt_ipv4.src)
                    pkt = packet.Packet()
                    pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,dst=pkt_ethernet.src,src=pkt_ethernet.dst))
                    pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,src=pkt_ipv4.dst,proto=pkt_ipv4.proto))
                    pkt.add_protocol(tcp.tcp(src_port=d_port,dst_port=s_port,seq=pkt_tcp.ack,ack=0, bits=4))
                    self._send_packet(datapath, in_port, pkt)
                    return 2
                else:
                    return 3
            else:
                return 1
        else:
            return 1           
            
        
    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        action = [parser.OFPActionOutput(port=port)]
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        out = parser.OFPPacketOut(datapath=datapath,buffer_id=ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER,actions=action,data=data)
        datapath.send_msg(out)