# -*- coding: utf-8 -*-
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.packet_base import packet_base
from pox.lib.packet.packet_utils import *
import pox.lib.packet as pkt
from pox.lib.recoco import Timer
import time
import re
import json

log = core.getLogger()

controller_start_time = 0
switches = ["s1", "s2", "s3", "s4", "s5"]
hosts = [{"name": "h1", "address": "10.0.0.1"}, {"name": "h2", "address": "10.0.0.2"}, 
         {"name": "h3", "address": "10.0.0.3"}, {"name": "h4", "address": "10.0.0.4"}, 
         {"name": "h5", "address": "10.0.0.5"}, {"name": "h6", "address": "10.0.0.6"}]
flow_table = [] # na poczatku wyobrazam sobie, ze to jest {"id": 1, "source": "h1", destination: "h6", "route": [switch1, switch2, switch3]}
dpids = {switch: 0 for switch in switches} # np. {"s1": 1, "s2": 2}
#dpids = {switch: index+1 for index, switch in enumerate(switches)}
interfaces = {"s1": [1,2,3,4,5,6], "s2": [1,2], "s3": [1,2], "s4": [1,2], "s5": [1,2,3,4,5,6]}
links = []
delays = {switch: 0 for switch in ["s2", "s3", "s4"]}
portstats_request_times = {switch: 0 for switch in ["s2", "s3","s4"]}
portstats_response_times = {switch: 0 for switch in ["s2", "s3","s4"]}
switch_controller_delays = {switch: 0 for switch in ["s2", "s3","s4"]}
switch_controller_delay = {switch: 0 for switch in ["s2", "s3","s4"]}
packets_sent = {switch: {interface: 0 for interface in interfaces[switch]} for switch in switches} 
packets_received = {switch: {interface: 0 for interface in interfaces[switch]} for switch in switches} ## jak wyżej, tylko że dla odebranych pakietów
packets_sent_old = {switch: {interface: 0 for interface in interfaces[switch]} for switch in switches} ## jak wyżej, tylko to wartość poprzednich statystyk
packets_received_old = {switch: {interface: 0 for interface in interfaces[switch]} for switch in switches} ## jak wyżej, tylko dla odebranych pakietów
packet_out_time = 0
packet_in_times = {"s2": 0, "s3": 0, "s4": 0}
IP = 0x0800
ARP = 0x0806

loaded_intents = []
monitored_intent = {}

def getTimestamp():
    return int(time.time() * 10000) - controller_start_time

class ProbePacket(packet_base):
      #My Protocol packet struct
  """
  myproto class defines our special type of packet to be sent all the way along including the link between the switches to measure link delays;
  it adds member attribute named timestamp to carry packet creation/sending time by the controller, and defines the 
  function hdr() to return the header of measurement packet (header will contain timestamp)
  """
  #For more info on packet_base class refer to file pox/lib/packet/packet_base.py

  def __init__(self):
     packet_base.__init__(self)
     self.timestamp=0

  def hdr(self, payload):
     return struct.pack('!I', self.timestamp) # code as unsigned int (I), network byte order (!, big-endian - the most significant byte of a word at the smallest memory address)

def send_probe_packets():
    for port in [4, 5, 6]:
        f = ProbePacket() #create a probe packet object
        e = pkt.ethernet() #create L2 type packet (frame) object
        e.src = EthAddr("ca:fe:ca:fe:ca:fe")
        e.dst = EthAddr("ca:fe:ca:fe:ca:fe")
        e.type=0x5577 #set unregistered EtherType in L2 header type field, here assigned to the probe packet type 
        msg = of.ofp_packet_out() #create PACKET_OUT message object
        msg.actions.append(of.ofp_action_output(port=port))
        f.timestamp = getTimestamp()
        e.payload = f
        msg.data = e.pack()
        send_message("s1", msg)

def handle_ConnectionDown (event):
  #Handle connection down - stop the timer for sending the probes
  global mytimer
  print "ConnectionDown: ", dpidToStr(event.connection.dpid)
  mytimer.cancel()

def getTheTime():
    flock = time.localtime()
    return "[%d-%02d-%02d]%02d.%02d.%02d" % (flock.tm_year, flock.tm_mon, flock.tm_mday, flock.tm_hour, flock.tm_min, flock.tm_sec)

def get_switch_by_dpid(dpid):
    switch = [key for key, value in dpids.items() if dpids[key] == dpid][0]
    return switch

def send_message(switch, message):
    #print(switch, dpids[switch])
    #print(core.openflow.getConnection(dpids[switch]))
    return core.openflow.getConnection(dpids[switch]).send(message)

def _timer_func():
    stat_request_message = of.ofp_stats_request(body=of.ofp_port_stats_request())
    for switch in ["s1", "s2", "s3", "s4", "s5"]:
        portstats_request_times[switch] = getTimestamp()
        if(switch in ["s2", "s3", "s4"]):
            send_message(switch, stat_request_message)
    send_probe_packets()
    print("Delays to switches: {}".format(delays))

def handle_portstats_received(event):
    # Observe the handling of port statistics provided by this function.
    dpid = event.connection.dpid
    switch = get_switch_by_dpid(dpid)
    portstats_response_times[switch] = getTimestamp()
    switch_controller_delay = (portstats_response_times[switch] - portstats_request_times[switch]) / 2
    switch_controller_delays[switch] = switch_controller_delay
    # print("{}: {} {} {}".format(switch, portstats_request_times[switch], portstats_response_times[switch], delay))
    for f in event.stats:
        port_number = int(f.port_no)
        if port_number >= 65534:
            continue
        packets_received_old[switch][port_number] = packets_received[switch][port_number]
        packets_received[switch][port_number] = f.rx_packets
        packets_sent_old[switch][port_number] = packets_sent[switch][port_number]
        packets_sent[switch][port_number] = f.tx_packets

def handle_ConnectionUp(event):
    # waits for connections from all switches, after connecting to all of them it starts a round robin timer for triggering h1-h4 routing changes
    dpid = event.connection.dpid
    #print("dpid ", dpid)
    # remember the connection dpid for the switch
    ports = event.connection.features.ports
    if len(ports) and re.match(r'^s\d', ports[0].name):
        switch = ports[0].name
        dpids[switch] = dpid
        print("Switch {} connected. DPID: {}".format(switch, dpid))
        setup_switch_host_connections(switch)
    else:
        print("Unrecognized switch connected with ports {}. DPID: {}".format([port.name for port in ports], dpid))
    # start 1-second recurring loop timer for round-robin routing changes; _timer_func is to be called on timer expiration to change the flow entry in s1
    if not any(dpid == 0 for dpid in [dpids[switch] for switch in ["s2", "s3", "s4", "s5"]]):
        Timer(1, _timer_func, recurring=True)
        process_intent()

def set_flow_by_destination(switch, destination, out_port):
    protocols = [IP, ARP]
    for protocol in protocols:
        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.dl_type = protocol
        msg.match.nw_dst = destination
        msg.actions.append(of.ofp_action_output(port=out_port))
        send_message(switch, msg)

def set_flow_by_in_port(switch, in_port, out_port):
    protocols = [IP, ARP]
    for protocol in protocols:
        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.dl_type = protocol
        msg.match.in_port = in_port
        msg.actions.append(of.ofp_action_output(port=out_port))
        send_message(switch, msg)

def setup_routing(switch):
    print("Setting up routing for {}".format(switch))
    if switch == "s1":
        for dst in ["10.0.0.4", "10.0.0.5", "10.0.0.6"]:
            set_flow_by_destination(switch=switch, destination=dst, out_port=5)
        set_flow_by_destination(switch=switch, destination="10.0.0.1", out_port=1)
        set_flow_by_destination(switch=switch, destination="10.0.0.2", out_port=2)
        set_flow_by_destination(switch=switch, destination="10.0.0.3", out_port=3)
    if switch == "s5":
        for dst in ["10.0.0.1", "10.0.0.2", "10.0.0.3"]:
            set_flow_by_destination(switch=switch, destination=dst, out_port=2)
        set_flow_by_destination(switch=switch, destination="10.0.0.4", out_port=4)
        set_flow_by_destination(switch=switch, destination="10.0.0.5", out_port=5)
        set_flow_by_destination(switch=switch, destination="10.0.0.6", out_port=6)
    if switch in ["s2", "s3", "s4"]:
        port_mapping = {1: 2, 2: 1}
        for in_port, out_port in port_mapping.items():
            set_flow_by_in_port(switch=switch, in_port=in_port, out_port=out_port)

def handle_received_probe(switch, packet):
    c = packet.find('ethernet').payload
    d,= struct.unpack('!I', c)
    delays[switch] = (getTimestamp() - switch_controller_delays[switch] - d) / 10
    # print(getTimestamp() - d - switch_controller_delays[switch])
    # print(switch_controller_delays[switch])

def handle_arp_packet(packet, connection):
    #obsługa ARP REQUEST Packet
    if packet.opcode == 1:
        msg = of.ofp_flow_mod()
        msg.priority =1
        msg.idle_timeout = 0
        msg.match.in_port =1
        msg.match.dl_type=0x0806
        msg.actions.append(of.ofp_action_output(port = 2))
        print("dpid: {} msg: {}".format(connection.dpid, msg))
        #if connection.dpid in dpids.values():
        connection.send(msg)
        

    #obłsuga ARP REPLY Packet
    if packet.opcode == 2:
        msg = of.ofp_flow_mod()
        msg.priority =1
        msg.idle_timeout = 0
        msg.match.in_port =2
        msg.match.dl_type=0x0806
        msg.actions.append(of.ofp_action_output(port = 1))
        #print("dpid: {} msg: {}".format(connection.dpid, msg))
        #if connection.dpid in dpids.values():
        connection.send(msg)

def handle_PacketIn(event):
    dpid = event.connection.dpid
    switch = get_switch_by_dpid(dpid)
    packet = event.parsed
    arp = packet.find("arp")
    # tu sie zwraca None
    ip = packet.find("ipv4")
    ethernet = packet.find("ethernet")

    #print("Pakiet ARP {}".format(arp))
    #print("JESTEM W HANLDE PACKET IN, pokaz mi swoj pakiecik i jego ip {} -  {}".format(packet, ip))
    #print("Switch {} doesnt know packet: {}".format(switch, packet.__dict__))
    if packet.type==0x5577: #0x5577 is unregistered EtherType, here assigned to 
        handle_received_probe(switch, packet)
    #so far tu nigdzie nie wchodzi

    if arp is not None:
        handle_arp_packet(arp, event.connection)

    if ip is not None:
        print("Switch {} wants to know how to forward an IP packet from {} to {}".format(ip.src, ip.dst))

    # setup_routing(switch)
    # print("Switch {} doesnt know how to handle packet: {}".format(switch, packet.__dict__))
    # if ip is not None:
    #     print("Switch {} wants to know how to forward an IP packet from {} to {}".format(ip.src, ip.dst))
    # setup_routing(switch)

def load_intents():
    f = open('intents.json')
    data = json.load(f)
    loaded_intents= data['intents']
    #for i in data['intents']:
        #print("intent: ", i)
    #monitored_intent = loaded_intents[0]
    f.close()
    print("Loaded intents {}".format(loaded_intents))

def map_host_name_to_address(host_name):
    for host in hosts:
        if host.name == host_name:
            return host.address
        
#s1 -> s2 -> s5 and back
def set_upper_route(source, destination):
    source_ip = map_host_name_to_address(source)
    destination_ip = map_host_name_to_address(destination)
    set_flow_by_destination(switch="s1", destination=destination_ip, out_port=4)
    set_flow_by_destination(switch="s5", destination=source_ip, out_port=1)

#s1 -> s3 -> s5 and back
def set_middle_route(source, destination):
    source_ip = map_host_name_to_address(source)
    destination_ip = map_host_name_to_address(destination)
    set_flow_by_destination(switch="s1", destination=destination_ip, out_port=5)
    set_flow_by_destination(switch="s5", destination=source_ip, out_port=2)

#s1 -> s4 -> s5 and back
def set_down_route(source, destination):
    source_ip = map_host_name_to_address(source)
    destination_ip = map_host_name_to_address(destination)
    set_flow_by_destination(switch="s1", destination=destination_ip, out_port=6)
    set_flow_by_destination(switch="s5", destination=source_ip, out_port=3)
    
def process_intent():
    #if monitored_intent == {}:
    #    monitored_intent = loaded_intents[0]
    #    print("monitored intent: {}", monitored_intent)

    f = open('intents.json')
    data = json.load(f)
    loaded_intents= data['intents']
    f.close()

    if(loaded_intents):
        intent = loaded_intents[0]
        print("intent: {}".format(intent))
    
    suitable_switch = {"switch": "", "delay": float('inf')}
    for interface_delay in delays:
        if interface_delay.value <= intent.latency and interface_delay.value < suitable_switch.delay :
            suitable_switch = interface_delay

    chosen_route = ""
    if suitable_switch == {"switch": "", "delay": float('inf')}:
        print("No suitable route available for max latency {}".format(intent.latency))
    elif suitable_switch.switch == "s2":
        set_upper_route(intent.source, intent.destination)
        chosen_route = "upper"
    elif suitable_switch.switch == "s3":
        set_middle_route(intent.source, intent.destination)
        chosen_route = "middle"
    elif suitable_switch.switch == "s4":
        set_down_route(intent.source, intent.destination)
        chosen_route = "down"
    
    flow_table.append({"id": (len(flow_table) + 1), 
                       "source": intent.source, 
                       "destination": intent.destination,
                       "route": chosen_route})

    #czy to jest wgl okej, to sie bedzie wywolywac po tym, jak switch stwierdzi, ze nie wie jak forwardowac pakiet
    #available_flow = {}
    #for flow in flows:
        #if(flow.source == source and flow.destination == destination):
            #available_flow = flow
            #break
    
    #to jest na pewno sytuacja, ze nie wiemy jak forwardowac pakiet, ale jak oblsugiwac te pakiety jak mamy pare flow na to samo src i dst ale z innym latency
    #przychodzi nam jakis pakiet to powinnismy tworzyc na podstawie jego intent czy wybierac
    #tylko wtedy mamy taki constraint, ze mamy liste intentow na kazdy mozliwy flow i 
    #stale latency i z tej listy wybieramy sobie pasujacy intent do naszego src i dst pakietu
    #no bo jak inaczej - przyjdzie nam pakiet o takim i takim src i dst i nie mamy dla niego intentu

    # print("Co nam tu przyszlo: {} {} {} {}".format(dpid, switch, source, destination))
    # if monitored_intent == {}:
    #     #iterujemy sobie po intentach i szukamy takiego, ktory bedzie miec matchujace src i dst
    #     for intent in load_intents:
    #         if intent.source == source and intent.destination == destination:
    #             monitored_intent = intent
    #             break
        
    #     print("monitored intent: {}".format(monitored_intent))
    #     max_latency = monitored_intent.latency
    #     for delay in delays:
    #         print("delay: {} delay value: {}".format(delay, delay.value))

        
    #     #set_flow_by_destination()
    # else:
    #     print("SIABADABA")

def setup_switch_host_connections(switch):
    if switch == "s1":
        set_flow_by_destination(switch="s1", destination="10.0.0.1", out_port=1)
        set_flow_by_destination(switch="s1", destination="10.0.0.2", out_port=2)
        set_flow_by_destination(switch="s1", destination="10.0.0.3", out_port=3)
        print("Host-switch {} configuration was completed".format(switch))

    if switch == "s5":
        set_flow_by_destination(switch="s5", destination="10.0.0.4", out_port=4)
        set_flow_by_destination(switch="s5", destination="10.0.0.5", out_port=5)
        set_flow_by_destination(switch="s5", destination="10.0.0.6", out_port=6)
        print("Host-switch {} configuration was completed".format(switch))

    if switch in ["s2", "s3", "s4"]:
        port_mapping = {1: 2, 2: 1}
        for in_port, out_port in port_mapping.items():
            set_flow_by_in_port(switch=switch, in_port=in_port, out_port=out_port)
    

def launch():

    global controller_start_time
    controller_start_time = getTimestamp()
    load_intents()
    # core is an instance of class POXCore (EventMixin) and it can register objects.
    # An object with name xxx can be registered to core instance which makes this object become a "component" available as pox.core.core.xxx.
    # for examples see e.g. https://noxrepo.github.io/pox-doc/html/#the-openflow-nexus-core-openflow
    # listen for port stats , https://noxrepo.github.io/pox-doc/html/#statistics-events
    core.openflow.addListenerByName(
        "PortStatsReceived", handle_portstats_received)
    # listen for the establishment of a new control channel with a switch, https://noxrepo.github.io/pox-doc/html/#connectionup
    core.openflow.addListenerByName("ConnectionUp", handle_ConnectionUp)
    # listen for the reception of packet_in message from switch, https://noxrepo.github.io/pox-doc/html/#packetin
    core.openflow.addListenerByName("PacketIn", handle_PacketIn)
