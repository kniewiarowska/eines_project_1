from pox.core import core
from pox.lib.util import dpidToStr
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
import pox.lib.packet as pkt
from pox.openflow.of_json import *
from pox.lib.recoco import Timer
import time
from pox.lib.packet.packet_base import packet_base
from pox.lib.packet.packet_utils import *
import struct

log = core.getLogger()

#global variables init

start_time = 0.0
sent_time1=0.0
sent_time2=0.0
received_time1 = 0.0
received_time2 = 0.0
src_dpid=0
dst_dpid=0
mytimer = 0
OWD1=0.0
OWD2=0.0


#probe protocol packet definition; only timestamp field is present in the header (no payload part)
class myproto(packet_base):
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


def _handle_ConnectionDown (event):
  #Handle connection down - stop the timer for sending the probes
  global mytimer
  print "ConnectionDown: ", dpidToStr(event.connection.dpid)
  mytimer.cancel()


#In the following, event.connection.dpid identifies the switch the message has been received from.

def _handle_ConnectionUp (event):
  #Handle connection up events to register a connecting switch in the controller

  global src_dpid, dst_dpid, mytimer
  print "ConnectionUp: ", dpidToStr(event.connection.dpid)

  #remember connection dpid between the controller and switch0 (src_dpid), and switch1 (dst_dpid)
  for m in event.connection.features.ports:
    if m.name == "s0-eth0":
      src_dpid = event.connection.dpid
    elif m.name == "s1-eth0":
      dst_dpid = event.connection.dpid

  #when the controller knows both src_dpid and dst_dpid are up, mytimer is started so that a probe packet is sent every 2 seconds across the link between respective switches
  if src_dpid<>0 and dst_dpid<>0:
    mytimer=Timer(2, _timer_func, recurring=True)
    #mytimer.start() #DB: mytimer.start() was originally used, now supressed for rising assertion error


def _handle_portstats_received (event):
   #Here, port statistics responses are handled to calculate delays T1 and T2 (see the lab instructions)

   global start_time, sent_time1, sent_time2, received_time1, received_time2, src_dpid, dst_dpid, OWD1, OWD2

   received_time = time.time() * 1000*10 - start_time
   #measure T1 as of lab guide
   if event.connection.dpid == src_dpid:
     OWD1=0.5*(received_time - sent_time1)
     #print "OWD1: ", OWD1, "ms"
 
   #measure T2 as of lab guide
   elif event.connection.dpid == dst_dpid:
     OWD2=0.5*(received_time - sent_time2) #originally sent_time1 was here
     #print "OWD2: ", OWD2, "ms"


def _handle_PacketIn (event):
  #This function is called to handle PACKET_IN messages received by the controller
 
  global start_time, OWD1, OWD2

  received_time = time.time() * 1000*10 - start_time #amount of time elapsed from start_time

  packet = event.parsed
  #print packet
 
  if packet.type==0x5577 and event.connection.dpid==dst_dpid: #0x5577 is unregistered EtherType, here assigned to probe packets
    #Process a probe packet received in PACKET_IN message from 'switch1' (dst_dpid), previously sent to 'switch0' (src_dpid) in PACKET_OUT.

    c=packet.find('ethernet').payload
    d,=struct.unpack('!I', c)  # note that d,=... is a struct.unpack and always returns a tuple
    print "[ms*10]: received_time=", int(received_time), ", d=", d, ", OWD1=", int(OWD1), ", OWD2=", int(OWD2)
    print "delay:", int(received_time - d - OWD1 - OWD2)/10, "[ms] <=====" # divide by 10 to normalise to milliseconds
  
  #Below, process the packet received in PACKET_IN if it's of other type allowed 
  a=packet.find('ipv4')
  b=packet.find('arp')
  if a:
    #print "IPv4 Packet:", packet
    msg = of.ofp_flow_mod()
    msg.priority =1
    msg.idle_timeout = 0
    msg.match.in_port =1
    msg.match.dl_type=0x0800
    msg.actions.append(of.ofp_action_output(port = 2))
    event.connection.send(msg)
  
    msg = of.ofp_flow_mod()
    msg.priority =1
    msg.idle_timeout = 0
    msg.match.in_port =2
    msg.match.dl_type=0x0800
    msg.actions.append(of.ofp_action_output(port = 1))
    event.connection.send(msg)   
 
  if b and b.opcode==1:
    #print "ARP Request Packet:", packet
    msg = of.ofp_flow_mod()
    msg.priority =1
    msg.idle_timeout = 0
    msg.match.in_port =1
    msg.match.dl_type=0x0806
    msg.actions.append(of.ofp_action_output(port = 2))
    if event.connection.dpid == src_dpid:
      #print "send to switch0"
      event.connection.send(msg)
    elif event.connection.dpid == dst_dpid:
      #print "send to switch1"
      event.connection.send(msg)
 
  if b and b.opcode==2:
    #print "ARP Reply Packet:", packet
    msg = of.ofp_flow_mod()
    msg.priority =1
    msg.idle_timeout = 0
    msg.match.in_port =2
    msg.match.dl_type=0x0806
    msg.actions.append(of.ofp_action_output(port = 1))
    if event.connection.dpid == src_dpid:
      #print "send to switch0"
      event.connection.send(msg)
    elif event.connection.dpid == dst_dpid:
      #print "send to switch1"
      event.connection.send(msg)


def _timer_func ():
  #This function is called periodically to send measurement-oriented messages to the switches.
  """
  Three OpenFlow commands are sent in sequence: one to measure T1, second to measure T3, and third to 
  measure T2 (see the lab instructions). T1 and T2 are used with ststistics requerst/response method
  (other OpenFlow command could be used), while T3 is measured with sending/receiving PACKET_OUT/PACKET_IN by 
  the controller. For more on the use of timers for non-blocking tasks in POX see section: "Threads, Tasks, and 
  Timers: pox.lib.recoco" in http://intronetworks.cs.luc.edu/auxiliary_files/mininet/poxwiki.pdf.
  NOTE: it may happen that trying to optimize signalling traffic the controller aggregates in one TCP segment
  multiple commands directed to a given switch. This may degrade the quality of measurements with hard to control
  delay variations. Little can be done about it without modyfying POX libraries and we rather have to live with this feature.
  """

  global start_time, sent_time1, sent_time2, src_dpid, dst_dpid
 
  #the following executes only when a connection to 'switch0' exists (otherwise AttributeError can be raised)
  if src_dpid <>0 and not core.openflow.getConnection(src_dpid) is None:

    #send out port_stats_request packet through switch0 connection src_dpid (to measure T1)
    core.openflow.getConnection(src_dpid).send(of.ofp_stats_request(body=of.ofp_port_stats_request()))
    sent_time1=time.time() * 1000*10 - start_time #sending time of stats_req: ctrl => switch0
    #print "sent_time1:", sent_time1

    #sequence of packet formating operations optimised to reduce the delay variation of e-2-e measurements (to measure T3)
    f = myproto() #create a probe packet object
    e = pkt.ethernet() #create L2 type packet (frame) object
    e.src = EthAddr("0:0:0:0:0:2")
    e.dst = EthAddr("0:1:0:0:0:1")
    e.type=0x5577 #set unregistered EtherType in L2 header type field, here assigned to the probe packet type 
    msg = of.ofp_packet_out() #create PACKET_OUT message object
    msg.actions.append(of.ofp_action_output(port=2)) #set the output port for the packet in switch0
    f.timestamp = int(time.time()*1000*10 - start_time) #set the timestamp in the probe packet
    #print f.timestamp
    e.payload = f
    msg.data = e.pack()
    core.openflow.getConnection(src_dpid).send(msg)
    print "=====> probe sent: f=", f.timestamp, " after=", int(time.time()*1000*10 - start_time), " [10*ms]"

  #the following executes only when a connection to 'switch1' exists (otherwise AttributeError can be raised)
  if dst_dpid <>0 and not core.openflow.getConnection(dst_dpid) is None:
    #send out port_stats_request packet through switch1 connection dst_dpid (to measure T2)
    core.openflow.getConnection(dst_dpid).send(of.ofp_stats_request(body=of.ofp_port_stats_request()))
    sent_time2=time.time() * 1000*10 - start_time #sending time of stats_req: ctrl => switch1
    #print "sent_time2:", sent_time2


def launch ():
  #This is launch function that POX calls to initialize the component (delay_measurement.py here).
  #This is usually a function actually named 'launch', though there are exceptions.
  #Fore more info: http://intronetworks.cs.luc.edu/auxiliary_files/mininet/poxwiki.pdf

  global start_time
  start_time = time.time() * 1000*10 # factor *10 applied to increase the accuracy for short delays (capture tenths of ms)
  print "start_time:", start_time/10

  #Below, set callbacks for the types of messages that can be sent by our switches and received by the controller
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  core.openflow.addListenerByName("ConnectionDown", _handle_ConnectionDown)
  core.openflow.addListenerByName("PortStatsReceived", _handle_portstats_received)
  core.openflow.addListenerByName("PacketIn", _handle_PacketIn)

