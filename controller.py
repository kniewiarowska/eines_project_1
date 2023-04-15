
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

s1_dpid = 0
s2_dpid = 0
s3_dpid = 0
s4_dpid = 0
s5_dpid = 0

s1_p1 = 0
s1_p4 = 0
s1_p5 = 0
s1_p6 = 0
s2_p1 = 0
s3_p1 = 0
s4_p1 = 0

pre_s1_p1 = 0
pre_s1_p4 = 0
pre_s1_p5 = 0
pre_s1_p6 = 0
pre_s2_p1 = 0
pre_s3_p1 = 0
pre_s4_p1 = 0


def getTheTime():  # function to create a timestamp
    flock = time.localtime()
    then = "[%s-%s-%s" % (str(flock.tm_year),
                          str(flock.tm_mon), str(flock.tm_mday))
    if int(flock.tm_hour) < 10:
        hrs = "0%s" % (str(flock.tm_hour))
    else:
        hrs = str(flock.tm_hour)
    if int(flock.tm_min) < 10:
        mins = "0%s" % (str(flock.tm_min))
    else:
        mins = str(flock.tm_min)

    if int(flock.tm_sec) < 10:
        secs = "0%s" % (str(flock.tm_sec))
    else:
        secs = str(flock.tm_sec)
    then += "]%s.%s.%s" % (hrs, mins, secs)
    return then


def _timer_func():
    global s1_dpid, s2_dpid, s3_dpid, s4_dpid, s5_dpid, turn
    core.openflow.getConnection(s1_dpid).send(
        of.ofp_stats_request(body=of.ofp_port_stats_request()))
    core.openflow.getConnection(s2_dpid).send(
        of.ofp_stats_request(body=of.ofp_port_stats_request()))
    core.openflow.getConnection(s3_dpid).send(
        of.ofp_stats_request(body=of.ofp_port_stats_request()))
    core.openflow.getConnection(s4_dpid).send(
        of.ofp_stats_request(body=of.ofp_port_stats_request()))


def _handle_portstats_received(event):
    # Observe the handling of port statistics provided by this function.
    global s1_dpid, s2_dpid, s3_dpid, s4_dpid, s5_dpid
    global s1_p1, s1_p4, s1_p5, s1_p6, s2_p1, s3_p1, s4_p1
    global pre_s1_p1, pre_s1_p4, pre_s1_p5, pre_s1_p6, pre_s2_p1, pre_s3_p1, pre_s4_p1
    if event.connection.dpid == s1_dpid:  # The DPID of one of the switches involved in the link
        for f in event.stats:
            if int(f.port_no) < 65534:
                if f.port_no == 1:
                    pre_s1_p1 = s1_p1
                    s1_p1 = f.rx_packets
                    # print "s1_p1->","TxDrop:", f.tx_dropped,"RxDrop:",f.rx_dropped,"TxErr:",f.tx_errors,"CRC:",f.rx_crc_err,"Coll:",f.collisions,"Tx:",f.tx_packets,"Rx:",f.rx_packets
                if f.port_no == 4:
                    pre_s1_p4 = s1_p4
                    s1_p4 = f.tx_packets
                    # s1_p4=f.tx_bytes
                    # print "s1_p4->","TxDrop:", f.tx_dropped,"RxDrop:",f.rx_dropped,"TxErr:",f.tx_errors,"CRC:",f.rx_crc_err,"Coll:",f.collisions,"Tx:",f.tx_packets,"Rx:",f.rx_packets
                if f.port_no == 5:
                    pre_s1_p5 = s1_p5
                    s1_p5 = f.tx_packets
                if f.port_no == 6:
                    pre_s1_p6 = s1_p6
                    s1_p6 = f.tx_packets

    if event.connection.dpid == s2_dpid:
        for f in event.stats:
            if int(f.port_no) < 65534:
                if f.port_no == 1:
                    pre_s2_p1 = s2_p1
                    s2_p1 = f.rx_packets
                    # s2_p1=f.rx_bytes

        print getTheTime(), "s1_p4(Sent):", (s1_p4 -
                                             pre_s1_p4), "s2_p1(Received):", (s2_p1 - pre_s2_p1)

    if event.connection.dpid == s3_dpid:
        for f in event.stats:
            if int(f.port_no) < 65534:
                if f.port_no == 1:
                    pre_s3_p1 = s3_p1
                    s3_p1 = f.rx_packets
        print getTheTime(), "s1_p5(Sent):", (s1_p5 -
                                             pre_s1_p5), "s3_p1(Received):", (s3_p1 - pre_s3_p1)

    if event.connection.dpid == s4_dpid:
        for f in event.stats:
            if int(f.port_no) < 65534:
                if f.port_no == 1:
                    pre_s4_p1 = s4_p1
                    s4_p1 = f.rx_packets
        print getTheTime(), "s1_p6(Sent):", (s1_p6 -
                                             pre_s1_p6), "s4_p1(Received):", (s4_p1 - pre_s4_p1)


def _handle_ConnectionUp(event):
    # waits for connections from all switches, after connecting to all of them it starts a round robin timer for triggering h1-h4 routing changes
    global s1_dpid, s2_dpid, s3_dpid, s4_dpid, s5_dpid
    print "ConnectionUp: ", dpidToStr(event.connection.dpid)
    # remember the connection dpid for the switch
    for m in event.connection.features.ports:
        if m.name == "s1-eth1":
            # s1_dpid: the DPID (datapath ID) of switch s1;
            s1_dpid = event.connection.dpid
            print "s1_dpid=", s1_dpid
        elif m.name == "s2-eth1":
            s2_dpid = event.connection.dpid
            print "s2_dpid=", s2_dpid
        elif m.name == "s3-eth1":
            s3_dpid = event.connection.dpid
            print "s3_dpid=", s3_dpid
        elif m.name == "s4-eth1":
            s4_dpid = event.connection.dpid
            print "s4_dpid=", s4_dpid
        elif m.name == "s5-eth1":
            s5_dpid = event.connection.dpid
            print "s5_dpid=", s5_dpid

    # start 1-second recurring loop timer for round-robin routing changes; _timer_func is to be called on timer expiration to change the flow entry in s1
    if s1_dpid <> 0 and s2_dpid <> 0 and s3_dpid <> 0 and s4_dpid <> 0 and s5_dpid <> 0:
        Timer(1, _timer_func, recurring=True)


def set_flow_by_destination(destination, out_port, event):
    protocols = [0x0800, 0x0806]
    for protocol in protocols:
        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.dl_type = protocol
        msg.match.nw_dst = destination
        msg.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(msg)


def set_flow_by_in_port(in_port, out_port, event):
    protocols = [0x0800, 0x0806]
    for protocol in protocols:
        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.dl_type = protocol
        msg.match.in_port = in_port
        msg.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(msg)


def _handle_PacketIn(event):

    global s1_dpid, s2_dpid, s3_dpid, s4_dpid, s5_dpid

    if event.connection.dpid == s1_dpid:

        for dst in ["10.0.0.4", "10.0.0.5", "10.0.0.6"]:

            set_flow_by_destination(destination=dst, out_port=5, event=event)

        set_flow_by_destination(destination="10.0.0.1",
                                out_port=1, event=event)

        set_flow_by_destination(destination="10.0.0.2",
                                out_port=2, event=event)

        set_flow_by_destination(destination="10.0.0.3",
                                out_port=3, event=event)

    if event.connection.dpid == s5_dpid:

        for dst in ["10.0.0.1", "10.0.0.2", "10.0.0.3"]:

            set_flow_by_destination(destination=dst, out_port=2, event=event)

        set_flow_by_destination(destination="10.0.0.4",
                                out_port=4, event=event)

        set_flow_by_destination(destination="10.0.0.5",
                                out_port=5, event=event)

        set_flow_by_destination(destination="10.0.0.6",
                                out_port=6, event=event)

    if event.connection.dpid in [s2_dpid, s3_dpid, s4_dpid]:
        port_mapping = {1: 2, 2: 1}
        for in_port, out_port in port_mapping.items():
            set_flow_by_in_port(
                in_port=in_port, out_port=out_port, event=event)


def launch():

    global start_time

    # core is an instance of class POXCore (EventMixin) and it can register objects.

    # An object with name xxx can be registered to core instance which makes this object become a "component" available as pox.core.core.xxx.

    # for examples see e.g. https://noxrepo.github.io/pox-doc/html/#the-openflow-nexus-core-openflow

    # listen for port stats , https://noxrepo.github.io/pox-doc/html/#statistics-events
    core.openflow.addListenerByName(
        "PortStatsReceived", _handle_portstats_received)

    # listen for the establishment of a new control channel with a switch, https://noxrepo.github.io/pox-doc/html/#connectionup
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)

    # listen for the reception of packet_in message from switch, https://noxrepo.github.io/pox-doc/html/#packetin
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
