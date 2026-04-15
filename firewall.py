from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4

class StaticFirewall(app_manager.RyuApp): #It initializes Ryu application
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION] #It uses OpenFlow 1.3 version to communicate with the switch

    def __init__(self, *args, **kwargs):
        super(StaticFirewall, self).__init__(*args, **kwargs) 
        # Initialize the MAC-to-Port dictionary for the learning switch
        self.mac_to_port = {} #Stores the MAC table remembers which MAC address belongs to which switch

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto # Extracts special ports and flags , like dictionary of keywords 
        parser = datapath.ofproto_parser #Used to build messages, like grammar builder
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] #To apply actions when match occurs
       #Creating flow rule 
        if buffer_id: #If the packet has been buffered by the switch, it would send buffer id to the controller
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, #Controller returns the rule along with the buffer id
                                    priority=priority, match=match, instructions=inst)
        else: #If the whole packet was sent to the controller, then the controller tells the rule and gives back the packet to the switch 
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod) #This transmits the message from controller to switch 
    #When a switch first connects to a controller, its flow table is completely empty. By default the switch will drop the packet, this prevents it
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER) 
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath #These extract necessary objects to communicate with the switch
        ofproto = datapath.ofproto #Imports protocol constants 
        parser = datapath.ofproto_parser #imports the functions needed to construct OpenFlow messages

        # 1. Install Table-Miss Flow Entry
        # This tells the switch: "If you don't have a rule for a packet, send it to the controller"
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions) #Forwards the packet directly to controller over OpenFlow control channel
        self.logger.info("Installed table-miss flow entry")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER) #This function handles packets sent from the switch to the controller.
    def _packet_in_handler(self, ev): #Extract info like packet, switch, where it came from 
        msg = ev.msg 
        datapath = msg.datapath # Switch 
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # Parse the packet, into redable format
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignore LLDP packets (switch discovery), used by switched to discover each other, not needed for rules
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst #Destination of packet
        src = eth.src # Source of packet
        dpid = datapath.id # Switch id

        self.mac_to_port.setdefault(dpid, {}) #Initialize MAC table

        # ========================================================
        # FIREWALL LOGIC 
        # ========================================================
        ip_pkt = pkt.get_protocol(ipv4.ipv4) #Checks if the packet has ipv4 address
        
        if ip_pkt:
            src_ip = ip_pkt.src # If it has ipv4 address, extract src and dst ip address
            dst_ip = ip_pkt.dst

            # FIREWALL RULE: Block traffic from h1 (10.0.0.1) to h2 (10.0.0.2)
            if src_ip == "10.0.0.1" and dst_ip == "10.0.0.2":
                # Log the blocked packet 
                self.logger.info("FIREWALL LOG: Blocked IPv4 packet from %s to %s", src_ip, dst_ip)
                
                # Match IPv4 packets from source IP to destination IP
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip) 
                self.add_flow(datapath, 100, match, []) #Creates high prio (100) rule to drop all IPv4 traffic from .1 to .2 directly at the switch
                
                return 

        # ========================================================
        # STANDARD LEARNING SWITCH LOGIC (Allows ARP and legal pings)
        # ========================================================
        
        # Learn the MAC address to avoid flooding next time
        self.mac_to_port[dpid][src] = in_port #Learn the source port

        # If we know where the destination MAC is, output to that port. Otherwise, send to all ports, except incoming
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst] 
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)] #Send the packet to the ports required as decided above

        # Install a flow so future packets don't have to visit the controller
        if out_port != ofproto.OFPP_FLOOD: #Packet with similar characterisitcs is handled by switch without involving controller
            #And also if you know the destination, not if you are flooding
            # If it's an IP packet, match on IP so we don't accidentally bypass our firewall with a broad MAC rule
            if ip_pkt:
                match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst)
            else: #For non-ip packets(ARP), matching is done using MAC address
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            
            if msg.buffer_id != ofproto.OFP_NO_BUFFER: #If packet is buffered apply the rule immediately
                self.add_flow(datapath, 10, match, actions, msg.buffer_id)
                return
            else: #If there is no buffer, the rule is installed for similar future packets
                self.add_flow(datapath, 10, match, actions)

        # Send the current packet out
        data = None #If switch already has the packet, don't send the full packet
        if msg.buffer_id == ofproto.OFP_NO_BUFFER: #If it is not buffered, switch does not have the packet stored
            data = msg.data #So, we send the full packet data from controller

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data) #creates an instruction for the switch to forward the packet
        datapath.send_msg(out) #Send the instruction to the switch
