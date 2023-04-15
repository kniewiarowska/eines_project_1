#!/usr/bin/python

"""
Create a 2-switch network, change link latency and measure the delay using ping. Wait for connecting to the controller to starting pinging.
The mininet network makes three passes, each ~15 sec long and each with a different value of the delay on the link between the switches.
Derived from: https://github.com/mininet/mininet/blob/master/examples/scratchnet.py and http://csie.nqu.edu.tw/smallko/sdn/latency.htm.
Note: you can change the duration of the experiment by adjusting the timers t1, t2 and the number of ICMP echo copies in option -c of the ping command
"""

from mininet.net import Mininet
from mininet.node import Node
from mininet.link import TCLink
from mininet.log import  setLogLevel, info
from threading import Timer
from mininet.util import quietRun
from time import sleep

def myNet(cname='controller', cargs='-v ptcp:'):
    "Create a two-switch network from scratch using Open vSwitch."
    info( "*** Creating nodes\n" )
    controller = Node( 'c0', inNamespace=False )
    switch = Node( 's0', inNamespace=False )
    switch1 = Node( 's1', inNamespace=False )
    h0 = Node( 'h0' )
    h1 = Node( 'h1' )

    "Initial link settings, initial delay of link switch-switch2 set to 10 ms"
    "host link delays set to 1ms"
    info( "*** Creating links\n" )
    linkopts0=dict(bw=100, delay='1ms', loss=0)
    linkopts1=dict(bw=100, delay='10ms', loss=0)
    link0=TCLink( h0, switch, **linkopts0)
    link1 = TCLink( switch, switch1, **linkopts1) #initially, the delay from switch to switch1 is 10ms
    link2 = TCLink( h1, switch1, **linkopts0)

    "print link0.intf1, link0.intf2"
    link0.intf2.setMAC("0:0:0:0:0:1")
    link1.intf1.setMAC("0:0:0:0:0:2")
    link1.intf2.setMAC("0:1:0:0:0:1")
    link2.intf2.setMAC("0:1:0:0:0:2")

    info( "*** Configuring hosts\n" )
    h0.setIP( '192.168.123.1/24' )
    h1.setIP( '192.168.123.2/24' )
    h0.setMAC("a:a:a:a:a:a")
    h1.setMAC("8:8:8:8:8:8")

    info( "*** Starting network using Open vSwitch\n" )
    switch.cmd( 'ovs-vsctl del-br dp0' )
    switch.cmd( 'ovs-vsctl add-br dp0' )
    switch1.cmd( 'ovs-vsctl del-br dp1' )
    switch1.cmd( 'ovs-vsctl add-br dp1' )

    controller.cmd( cname + ' ' + cargs + '&' )
    for intf in switch.intfs.values():
        print intf
        print switch.cmd( 'ovs-vsctl add-port dp0 %s' % intf )

    for intf in switch1.intfs.values():
        print intf
        print switch1.cmd( 'ovs-vsctl add-port dp1 %s' % intf )

    "Setting the connections from the switches to the controller"
    # Note: controller and switch are in root namespace, and we
    # can connect them via the loopback interface; otherwise
    # external IP address of the controller should be specified below
    switch.cmd( 'ovs-vsctl set-controller dp0 tcp:127.0.0.1:6633') # for the switch and controller both attached to localhost
    switch1.cmd( 'ovs-vsctl set-controller dp1 tcp:127.0.0.1:6633') # for the switch and controller both attached to localhost

    info( '*** Waiting for switches to connect to the controller' )
    while 'is_connected' not in quietRun( 'ovs-vsctl show' ):
        sleep( 1 )
        info( '.' )
    info( '\n' )

    def cDelay1(): #function called back to set the link delay to 50 ms; both directions have to be set
       #switch.cmdPrint('ethtool -K s0-eth1 gro off') #not supported by VBox, use the tc tool as below
       switch.cmdPrint('tc qdisc del dev s0-eth1 root')
       switch.cmdPrint('tc qdisc add dev s0-eth1 root handle 10: netem delay 50ms')  #originally 50ms
       #switch1.cmdPrint('ethtool -K s1-eth0 gro off') #not supported by VBox, use the tc tool as below
       switch1.cmdPrint('tc qdisc del dev s1-eth0 root')
       switch1.cmdPrint('tc qdisc add dev s1-eth0 root handle 10: netem delay 50ms') #originally 50 ms
       info( '+++++++++++++ 50ms delay started\n' )

    def cDelay2(): #function called back to set the link delay to 200ms
       #switch.cmdPrint('ethtool -K s0-eth1 gro off')  #ethtool works for GRO only on specific interfaces
       switch.cmdPrint('tc qdisc del dev s0-eth1 root')
       switch.cmdPrint('tc qdisc add dev s0-eth1 root handle 10: netem delay 200ms')  #originally 200ms
       #switch1.cmdPrint('ethtool -K s1-eth0 gro off') #ethtool works for GRO only on specific interfaces
       switch1.cmdPrint('tc qdisc del dev s1-eth0 root')
       switch1.cmdPrint('tc qdisc add dev s1-eth0 root handle 10: netem delay 200ms') #originally 200ms
       info( '+++++++++++++ 200ms delay started\n' )

    # From this moment, the network is going to route with the inter-switch link delay equal 10 ms (inintial value)
    # The two timers set below will set two another link delay values in the 15th and 30th second of the experiment.
    # Note: 45sec long ping run determines the duration of the whole experiment.

    info( '+++++++++++++ Setting t1   ' )
    "Timer t1 is set to trigger function cDelay1 after the period of 21 sec which will set link delay to 200ms"
    "When t1 expires, cDelay1 is triggered and link delay is set to 50ms"
    t1=Timer(21, cDelay1)
    t1.start()
    info( '+++++++++++++ t1 started\n' )

    info( '+++++++++++++ Setting t2   ' )
    "36 seconds later, link delay from switch to switch 1 will change to 200ms"
    "The whole procedure is analogous to the t1 case commented above"
    t2=Timer(36, cDelay2)
    t2.start()
    info( '+++++++++++++ t2 started\n' )

    info( "\n*** Running the test\n\n" )

    # Generate 45 ICMP echo requests, one per second, which accounts to 45 seconds
    " The script will stay in this ping phase for 51 seconds only being interrupted by t1 and t2."
    " All values (includig -c 51 in the ping command) have been tuned to provide an equal"
    " number of 15 ICMP echoes in each iteration."
    " Note also h0-to-h1 ping delay (RTT) will include delays h0-switch and switch1-h1"
    h0.cmdPrint( 'ping -i 1 -c 51 ' + h1.IP() )

    sleep( 1 )
    info( "*** Stopping the network\n" )
    controller.cmd( 'kill %' + cname )
    switch.cmd( 'ovs-vsctl del-br dp0' )
    switch.deleteIntfs()
    switch1.cmd( 'ovs-vsctl del-br dp1' )
    switch1.deleteIntfs()
    info( '\n' )

if __name__ == '__main__':
    setLogLevel( 'info' )
    info( '*** Scratch network demo (kernel datapath)\n' )
    Mininet.init()
    myNet()

