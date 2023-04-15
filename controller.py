
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


log = core.getLogger()

switches = ["s1", "s2", "s3", "s4", "s5", "s6"]
dpids = {switch: 0 for switch in switches} # np. {"s1": 1, "s2": 2}
interfaces = {"s1": [1,2,3,4,5,6], "s2": [1,2], "s3": [1,2], "s4": [1,2], "s5": [1,2,3,4,5,6]}
links = []
packets_sent = {switch: {interface: 0 for interface in interfaces[switch]} for switch in switches} # np. {"s1": {1: 0, 2: 0, 3:0, 4:0, 5:0, 6:0}, "s2": ...} mapuje switche na słowniki {nr_interfejsu: liczba_wyslanych_pakietów}
packets_received = {switch: {interface: 0 for interface in interfaces[switch]} for switch in switches} # jak wyżej, tylko że dla odebranych pakietów
packets_sent_old = {switch: {interface: 0 for interface in interfaces[switch]} for switch in switches} # jak wyżej, tylko to wartość poprzednich statystyk
packets_received_old = {switch: {interface: 0 for interface in interfaces[switch]} for switch in switches} # jak wyżej, tylko dla odebranych pakietów

IP = 0x0800
ARP = 0x0806

def getTheTime():
    flock = time.localtime()
    return "[%d-%02d-%02d]%02d.%02d.%02d" % (flock.tm_year, flock.tm_mon, flock.tm_mday, flock.tm_hour, flock.tm_min, flock.tm_sec)

def get_switch_by_dpid(dpid)
    switch = [key for key, value in dpids.items() if dpids[value] == dpid][0]
    return switch

def send_message(switch, message):
    return core.openflow.getConnection(dpids[switch], message)

def _timer_func():
    stat_request_message = of.ofp_stats_request(body=of.ofp_port_stats_request())
    for switch in ["s1", "s2", "s3", "s4"]:
        send_message(switch, stat_request_message)

def handle_portstats_received(event):
    # Observe the handling of port statistics provided by this function.
    dpid = event.connection.dpid
    switch = get_switch_by_dpid(dpid)
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
    print "ConnectionUp: ", dpidToStr(event.connection.dpid)
    # remember the connection dpid for the switch
    for m in event.connection.features.ports:
        pattern = r'^s\d+-eth\d+$'
        if re.match(pattern, m.name):
            switch = m.name.split("-")[0]
            dpids[switch] = event.connection.dpid
            print("{} DPID: {}".format(switch, dpids[switch]))
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
        send_message(switch)

def handle_PacketIn(event):
    dpid = event.connection.dpid
    switch = get_switch_by_dpid(dpid)
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


def launch():

    global start_time
    # core is an instance of class POXCore (EventMixin) and it can register objects.
    # An object with name xxx can be registered to core instance which makes this object become a "component" available as pox.core.core.xxx.
    # for examples see e.g. https://noxrepo.github.io/pox-doc/html/#the-openflow-nexus-core-openflow
    # listen for port stats , https://noxrepo.github.io/pox-doc/html/#statistics-events
    core.openflow.addListenerByName(
        "PortStatsReceived", _handle_portstats_received)
    # listen for the establishment of a new control channel with a switch, https://noxrepo.github.io/pox-doc/html/#connectionup
    core.openflow.addListenerByName("ConnectionUp", handle_ConnectionUp)
    # listen for the reception of packet_in message from switch, https://noxrepo.github.io/pox-doc/html/#packetin
    core.openflow.addListenerByName("PacketIn", handle_PacketIn)
