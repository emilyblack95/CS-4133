"""
Project 5 Topology
Created on: Nov 17, 2018
Author: emilyblack95
Source: https://github.com/mininet/mininet/blob/master/custom/topo-2sw-2host.py
Two directly connected switches plus a host for each switch:
   host --- switch --- switch --- host
Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo
from mininet.link import TCLink

class MyTopo( Topo ):
    "Project 5 topology."

    def __init__( self ):
        # Initialize topology
        Topo.__init__( self )

        # Add hosts
        aHost = self.addHost('aHost', ip='10.0.0.1', mac='00:00:00:00:00:01')
        bHost = self.addHost('bHost', ip='10.0.0.2', mac='00:00:00:00:00:02')
        cHost = self.addHost('cHost', ip='10.0.0.3', mac='00:00:00:00:00:03')
        dHost = self.addHost('dHost', ip='10.0.0.4', mac='00:00:00:00:00:04')
        eHost = self.addHost('eHost', ip='10.0.0.5', mac='00:00:00:00:00:05')
        fHost = self.addHost('fHost', ip='10.0.0.6', mac='00:00:00:00:00:06')
        gHost = self.addHost('gHost', ip='10.0.0.7', mac='00:00:00:00:00:07')
        hHost = self.addHost('hHost', ip='10.0.0.8', mac='00:00:00:00:00:08')
        iHost = self.addHost('iHost', ip='10.0.0.9', mac='00:00:00:00:00:09')
        jHost = self.addHost('jHost', ip='10.0.0.10', mac='00:00:00:00:00:10')
        kHost = self.addHost('kHost', ip='10.0.0.11', mac='00:00:00:00:00:11')
        lHost = self.addHost('lHost', ip='10.0.0.12', mac='00:00:00:00:00:12')

        # Add switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')
        s6 = self.addSwitch('s6')
        s7 = self.addSwitch('s7')
        s8 = self.addSwitch('s8')
        s9 = self.addSwitch('s9')
        s10 = self.addSwitch('s10')
        s11 = self.addSwitch('s11')
        s12 = self.addSwitch('s12')

        # Add links
        self.addLink(aHost, s1)
        self.addLink(bHost, s2)
        self.addLink(cHost, s3)
        self.addLink(dHost, s4)
        self.addLink(eHost, s5)
        self.addLink(fHost, s6)
        self.addLink(gHost, s7)
        self.addLink(hHost, s8)
        self.addLink(iHost, s9)
        self.addLink(jHost, s10)
        self.addLink(kHost, s11)
        self.addLink(lHost, s12)

        self.addLink(s3, s1)
        self.addLink(s3, s2)
        self.addLink(s3, s4)
        self.addLink(s4, s2, bw=5, delay='2ms', loss=2)
        self.addLink(s1, s2)
        self.addLink(s1, s4)
        self.addLink(s2, s5)
        self.addLink(s5, s6)
        self.addLink(s5, s7)
        self.addLink(s6, s7)
        self.addLink(s6, s12)
        self.addLink(s6, s11)
        self.addLink(s11, s12)
        self.addLink(s7, s8)
        self.addLink(s7, s10)
        self.addLink(s7, s9)
        self.addLink(s8, s10)
        self.addLink(s9, s10)
        self.addLink(s8, s9)

topos = { 'mytopo': ( lambda: MyTopo() ) }
