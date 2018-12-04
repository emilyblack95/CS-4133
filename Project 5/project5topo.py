"""
Project 5 Topology
Created on: Nov 17, 2018
Author: emilyblack95
Source: https://github.com/mininet/mininet/blob/master/custom/topo-2sw-2host.py
To run this topology, simply run: Sudo mn --custom project5topo.py --topo mytopo
Commands (host to host ping isnt available):
- nodes (to see available nodes)
- h1 ping -c 1 s2 (host 1 pings one packet to host 2)
- Can ping switch to switch and host to switch (or vise versa)
- dump (shows info about custom stuff)
"""

from mininet.topo import Topo
from mininet.link import TCLink

class MyTopo( Topo ):
    "Project 5 topology."

    def __init__( self ):
        # Initialize topology
        Topo.__init__( self )

        # Add hosts
        aHost = self.addHost('h1', ip='10.0.0.1', mac='00:00:00:00:00:01')
        bHost = self.addHost('h2', ip='10.0.0.2', mac='00:00:00:00:00:02')
        cHost = self.addHost('h3', ip='10.0.0.3', mac='00:00:00:00:00:03')
        dHost = self.addHost('h4', ip='10.0.0.4', mac='00:00:00:00:00:04')
        eHost = self.addHost('h5', ip='10.0.0.5', mac='00:00:00:00:00:05')
        fHost = self.addHost('h6', ip='10.0.0.6', mac='00:00:00:00:00:06')
        gHost = self.addHost('h7', ip='10.0.0.7', mac='00:00:00:00:00:07')
        hHost = self.addHost('h8', ip='10.0.0.8', mac='00:00:00:00:00:08')
        iHost = self.addHost('h9', ip='10.0.0.9', mac='00:00:00:00:00:09')
        jHost = self.addHost('h10', ip='10.0.0.10', mac='00:00:00:00:00:A1')
        kHost = self.addHost('h11', ip='10.0.0.11', mac='00:00:00:00:00:B1')
        lHost = self.addHost('h12', ip='10.0.0.12', mac='00:00:00:00:00:C1')

        # Add switches
        switch1 = self.addSwitch('s1',bw=10,delay='7ms',loss=2)
        switch2 = self.addSwitch('s2',bw=9,delay='5ms',loss=0)
        switch3 = self.addSwitch('s3',bw=4,delay='4ms',loss=9)
        switch4 = self.addSwitch('s4',bw=6,delay='2ms',loss=11)
        switch5 = self.addSwitch('s5',bw=7,delay='1ms',loss=5)
        switch6 = self.addSwitch('s6',bw=2,delay='3ms',loss=4)
        switch7 = self.addSwitch('s7',bw=7,delay='11ms',loss=1)
        switch8 = self.addSwitch('s8',bw=3,delay='9ms',loss=6)
        switch9 = self.addSwitch('s9',bw=1,delay='1ms',loss=7)
        switch10 = self.addSwitch('s10',bw=12,delay='6ms',loss=2)
        switch11 = self.addSwitch('s11',bw=14,delay='8ms',loss=3)
        switch12 = self.addSwitch('s12',bw=9,delay='2ms',loss=5)

        # Add links
        self.addLink(aHost, switch1)
        self.addLink(bHost, switch2)
        self.addLink(cHost, switch3)
        self.addLink(dHost, switch4)
        self.addLink(eHost, switch5)
        self.addLink(fHost, switch6)
        self.addLink(gHost, switch7)
        self.addLink(hHost, switch8)
        self.addLink(iHost, switch9)
        self.addLink(jHost, switch10)
        self.addLink(kHost, switch11)
        self.addLink(lHost, switch12)

        self.addLink(switch3, switch1)
        self.addLink(switch3, switch2)
        self.addLink(switch3, switch4)
        self.addLink(switch4, switch2)
        self.addLink(switch1, switch2)
        self.addLink(switch1, switch4)
        self.addLink(switch2, switch5)
        self.addLink(switch5, switch6)
        self.addLink(switch5, switch7)
        self.addLink(switch6, switch7)
        self.addLink(switch6, switch12)
        self.addLink(switch6, switch11)
        self.addLink(switch11, switch12)
        self.addLink(switch7, switch8)
        self.addLink(switch7, switch10)
        self.addLink(switch7, switch9)
        self.addLink(switch8, switch10)
        self.addLink(switch9, switch10)
        self.addLink(switch8, switch9)

topos = { 'mytopo': ( lambda: MyTopo() ) }
