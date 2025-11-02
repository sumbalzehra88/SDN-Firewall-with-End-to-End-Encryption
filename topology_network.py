#!/usr/bin/env python3
"""
Full Mininet topology: HQ ↔ Cloud ↔ Branch
Works with Ryu firewall controller (controller_firewall.py)
"""

from mininet.net import Mininet
from mininet.node import Node, RemoteController, OVSSwitch
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink


# ---------- Router Node Definition ----------
class LinuxRouter(Node):
    """Node with IP forwarding enabled."""
    def config(self, **params):
        super().config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        super().terminate()


# ---------- Topology Definition ----------
class OfficeNetwork(Topo):
    def build(self):
        # HQ side
        hqpc1 = self.addHost('hqpc1', ip='10.0.1.10/24', defaultRoute='via 10.0.1.1')
        hqpc2 = self.addHost('hqpc2', ip='10.0.1.11/24', defaultRoute='via 10.0.1.1')
        s1 = self.addSwitch('s1')
        rHQ = self.addNode('rHQ', cls=LinuxRouter, ip='10.0.1.1/24')

        # Branch side
        brpc1 = self.addHost('brpc1', ip='10.0.2.10/24', defaultRoute='via 10.0.2.1')
        brpc2 = self.addHost('brpc2', ip='10.0.2.11/24', defaultRoute='via 10.0.2.1')
        s2 = self.addSwitch('s2')
        rBR = self.addNode('rBR', cls=LinuxRouter, ip='10.0.2.1/24')

        # Cloud router (interconnect)
        cloud = self.addNode('cloud', cls=LinuxRouter, ip='10.0.100.1/24')

        # HQ connections
        self.addLink(hqpc1, s1)
        self.addLink(hqpc2, s1)
        self.addLink(s1, rHQ, intfName2='rHQ-eth1', params2={'ip': '10.0.1.1/24'})

        # Branch connections
        self.addLink(brpc1, s2)
        self.addLink(brpc2, s2)
        self.addLink(s2, rBR, intfName2='rBR-eth1', params2={'ip': '10.0.2.1/24'})

        # Cloud links (interconnecting HQ, Branch, Cloud)
        self.addLink(rHQ, cloud,
                     intfName1='rHQ-eth2', params1={'ip': '10.0.100.2/24'},
                     intfName2='cloud-eth1', params2={'ip': '10.0.100.1/24'})

        self.addLink(rBR, cloud,
                     intfName1='rBR-eth2', params1={'ip': '10.0.101.2/24'},
                     intfName2='cloud-eth2', params2={'ip': '10.0.101.1/24'})


# ---------- Run Network ----------
def run():
    topo = OfficeNetwork()
    net = Mininet(topo=topo, controller=None, switch=OVSSwitch, link=TCLink, waitConnected=True)

    info('\n*** Adding Ryu controller\n')
    c0 = net.addController('c0', controller=RemoteController,
                           ip='127.0.0.1', port=6653)

    info('\n*** Starting network\n')
    net.start()

    # Optional small delay for controller registration
    import time
    time.sleep(2)

    info('\n*** Setting up static routes\n')
    rHQ = net['rHQ']
    rBR = net['rBR']
    cloud = net['cloud']

    # HQ router routes to branch via cloud
    rHQ.cmd('ip route add 10.0.2.0/24 via 10.0.100.1')

    # Branch router routes to HQ via cloud
    rBR.cmd('ip route add 10.0.1.0/24 via 10.0.101.1')

    # Cloud router routes
    cloud.cmd('ip route add 10.0.1.0/24 via 10.0.100.2')
    cloud.cmd('ip route add 10.0.2.0/24 via 10.0.101.2')

    info('\n*** Network ready! Launching CLI...\n')
    CLI(net)

    info('\n*** Stopping network\n')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()

