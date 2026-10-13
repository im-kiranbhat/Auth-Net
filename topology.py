#!/usr/bin/env python3
"""Mininet topology for the authentication/network-access-control lab."""
from pathlib import Path
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

BASE_DIR = Path(__file__).resolve().parent
SERVICE_FILE = BASE_DIR / "protected_service.py"

class AuthTopo(Topo):
    def build(self):
        self.addSwitch("s1", protocols="OpenFlow13", failMode="secure")
        self.addSwitch("s2", protocols="OpenFlow13", failMode="secure")
        self.addHost("h2", ip="10.0.0.2/24")
        self.addHost("h3", ip="10.0.0.3/24")
        self.addHost("h4", ip="10.0.0.4/24")
        self.addLink("h2", "s1")
        self.addLink("h3", "s1")
        self.addLink("s1", "s2")
        self.addLink("s2", "h4")

def main():
    setLogLevel("info")
    net = Mininet(topo=AuthTopo(), controller=None, switch=OVSSwitch, autoSetMacs=True)
    try:
        info("*** Starting network\n")
        net.start()
        for sw in net.switches:
            sw.cmd(f"ovs-ofctl -O OpenFlow13 add-flow {sw.name} 'priority=0,actions=NORMAL'")
            sw.cmd(f"ovs-ofctl -O OpenFlow13 add-flow {sw.name} 'priority=150,ip,tcp,nw_dst=10.0.0.4,tp_dst=9000,actions=drop'")
        info("*** Hosts: h2=10.0.0.2, h3=10.0.0.3, h4=10.0.0.4\n")
        info(f"*** Protected service file: {SERVICE_FILE}\n")
        info("*** At mininet> start service with: h4 python3 " + str(SERVICE_FILE) + " --host 10.0.0.4 --port 9000 &\n")
        info("*** Useful checks: nodes, net, pingall\n")
        CLI(net)
    finally:
        info("*** Stopping network and cleaning Mininet nodes\n")
        net.stop()

if __name__ == "__main__":
    main()
