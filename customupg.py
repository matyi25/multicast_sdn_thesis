"""Custom topology h3
                  /
   h1 -       --s10--     -- h4
       \     /      \   /
        \   /        \ /
   h2 -- s9          s11--- h5
          \
           \
            s12 ----s13
            /       / \
           h6      h7  h8

h1: ip=10.0.0.1 mac=00:00:00:00:00:01     s9: dpid=00-00-00-00-00-09
h2: ip=10.0.0.2 mac=00:00:00:00:00:02     s10: dpid=00-00-00-00-00-0a
h3: ip=10.0.0.3 mac=00:00:00:00:00:03     s11: dpid=00-00-00-00-00-0b
h4: ip=10.0.0.4 mac=00:00:00:00:00:04     s12: dpid=00-00-00-00-00-0c
h5: ip=10.0.0.5 mac=00:00:00:00:00:05     s13: dpid=00-00-00-00-00-0d
h6: ip=10.0.0.6 mac=00:00:00:00:00:06
h7: ip=10.0.0.7 mac=00:00:00:00:00:07
h8: ip=10.0.0.8 mac=00:00:00:00:00:08

start as:
  sudo -E mn --switch=user --controller=remote --mac --custom customupg.py
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        h1 = self.addHost( 'h1', defaultRoute='h1-eth0' )
        h2 = self.addHost( 'h2', defaultRoute='h2-eth0' )
        h3 = self.addHost( 'h3', defaultRoute='h3-eth0' )
        h4 = self.addHost( 'h4', defaultRoute='h4-eth0' )
        h5 = self.addHost( 'h5', defaultRoute='h5-eth0' ) 
        h6 = self.addHost( 'h6', defaultRoute='h6-eth0' )
        h7 = self.addHost( 'h7', defaultRoute='h7-eth0' )
        h8 = self.addHost( 'h8', defaultRoute='h8-eth0' )
        s9 = self.addSwitch( 's9' )
        s10 = self.addSwitch( 's10' )
        s11 = self.addSwitch( 's11' )
        s12 = self.addSwitch( 's12' )
        s13 = self.addSwitch( 's13' )

        # Add links
        self.addLink( s9, h1 )
        self.addLink( s9, h2 )
        self.addLink( s9, s10 )
        self.addLink( s9, s12 )
        self.addLink( s10, h3 )
        self.addLink( s10, s11 )
        self.addLink( s11, h4 )
        self.addLink( s11, h5 )
        self.addLink( s12, h6 )
        self.addLink( s12, s13 )
        self.addLink( s13, h7 )
        self.addLink( s13, h8 )
        
     

topos = { 'minimal': ( lambda: MyTopo() ) }
