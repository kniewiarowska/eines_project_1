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
dpids = {switch: 0 for switch in switches} # np. {"s1": 1, "s2": 2}
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
    # remember the connection dpid for the switch
    ports = event.connection.features.ports
    if len(ports) and re.match(r'^s\d', ports[0].name):
        switch = ports[0].name
        dpids[switch] = dpid
        print("Switch {} connected. DPID: {}".format(switch, dpid))
    else:
        print("Unrecognized switch connected with ports {}. DPID: {}".format([port.name for port in ports], dpid))
    # start 1-second recurring loop timer for round-robin routing changes; _timer_func is to be called on timer expiration to change the flow entry in s1
    if not any(dpid == 0 for dpid in [dpids[switch] for switch in ["s2", "s3", "s4", "s5"]]):
        Timer(1, _timer_func, recurring=True)

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
    c=packet.find('ethernet').payload
    d,= struct.unpack('!I', c)
    delays[switch] = (getTimestamp() - switch_controller_delays[switch] - d) / 10
    # print(getTimestamp() - d - switch_controller_delays[switch])
    # print(switch_controller_delays[switch])

def handle_PacketIn(event):
    dpid = event.connection.dpid
    print(dir(dpid))
    print(dir(event.connection))
    print(core.openflow.getConnection(dpid))

    switch = get_switch_by_dpid(dpid)
    packet = event.parsed
    arp = packet.find("arp")
    ip = packet.find("ipv4")
    if packet.type==0x5577: #0x5577 is unregistered EtherType, here assigned to 
        handle_received_probe(switch, packet)
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
    for i in data['intents']:
        print("intent: ", i)
    f.close()

def process_intent(intent):
    if(monitored_intent == {}):
        monitored_intent = intent


def launch():

    global controller_start_time
    controller_start_time = getTimestamp()
    load_intents()
    setup_routing("s1")
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
