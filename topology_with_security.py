#!/usr/bin/env python3
"""
Full Mininet topology with SECURITY INTEGRATION
HQ ↔ Cloud ↔ Branch with encryption and Zero Trust
"""

from mininet.net import Mininet
from mininet.node import Node, RemoteController, OVSSwitch
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time
import sys
import os

# Fix import path for security_module
# Get the directory where this script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

# Import security module
try:
    from security_module import SecureHost as SecurityManager
except ImportError as e:
    print(f"❌ ERROR: Could not import security_module: {e}")
    print(f"   Make sure security_module.py is in: {SCRIPT_DIR}")
    sys.exit(1)


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


# ---------- Security Functions ----------
class NetworkSecurityManager:
    """Manages security for all hosts in the network"""
    
    def __init__(self, net):
        self.net = net
        self.security_hosts = {}
        self.verified_pairs = set()
        
        info('\n*** 🔐 Initializing Network Security Manager\n')
        self._initialize_security()
    
    def _initialize_security(self):
        """Create security modules for all hosts"""
        host_names = ['hqpc1', 'hqpc2', 'brpc1', 'brpc2']
        
        for host_name in host_names:
            info(f'🔐 Setting up security for {host_name}...\n')
            try:
                self.security_hosts[host_name] = SecurityManager(host_name)
            except Exception as e:
                info(f'❌ Failed to setup security for {host_name}: {e}\n')
                raise
        
        info('✅ All hosts secured!\n')
    
    def authenticate_hosts(self, host1_name, host2_name):
        """Perform Zero Trust authentication between two hosts"""
        info(f'\n🔐 Zero Trust Authentication: {host1_name} ↔ {host2_name}\n')
        
        host1_sec = self.security_hosts[host1_name]
        host2_sec = self.security_hosts[host2_name]
        
        # Mutual authentication
        identity1 = host1_sec.sign_identity()
        identity2 = host2_sec.sign_identity()
        
        verified1 = host2_sec.verify_host(host1_sec.public_key, identity1)
        verified2 = host1_sec.verify_host(host2_sec.public_key, identity2)
        
        if verified1 and verified2:
            self.verified_pairs.add((host1_name, host2_name))
            self.verified_pairs.add((host2_name, host1_name))
            info(f'✅ Mutual authentication successful!\n')
            return True
        else:
            info(f'❌ Authentication failed!\n')
            return False
    
    def exchange_session_keys(self, host1_name, host2_name):
        """Exchange session keys between two authenticated hosts"""
        pair = (host1_name, host2_name)
        if pair not in self.verified_pairs:
            info(f'❌ Hosts not verified! Authenticate first.\n')
            return False
        
        info(f'\n🔑 Exchanging session keys: {host1_name} ↔ {host2_name}\n')
        
        host1_sec = self.security_hosts[host1_name]
        host2_sec = self.security_hosts[host2_name]
        
        # Host1 shares key with Host2
        encrypted_key = host1_sec.encrypt_session_key(host2_sec.public_key)
        received_key = host2_sec.decrypt_session_key(encrypted_key)
        
        if received_key:
            from cryptography.fernet import Fernet
            host2_sec.fernet_key = received_key
            host2_sec.cipher = Fernet(received_key)
            info(f'✅ Session key exchanged successfully!\n')
            return True
        
        info(f'❌ Key exchange failed!\n')
        return False
    
    def send_encrypted_message(self, src_name, dst_name, message):
        """Send encrypted message from source to destination"""
        if (src_name, dst_name) not in self.verified_pairs:
            info(f'❌ Hosts not authenticated!\n')
            return None
        
        src_sec = self.security_hosts[src_name]
        
        info(f'\n📨 {src_name} → {dst_name} (encrypted)\n')
        info(f'   Plaintext: {message}\n')
        
        encrypted = src_sec.encrypt_data(message)
        info(f'   Encrypted: {encrypted[:50]}...\n')
        
        return encrypted
    
    def receive_encrypted_message(self, dst_name, encrypted_data):
        """Receive and decrypt message at destination"""
        dst_sec = self.security_hosts[dst_name]
        
        decrypted = dst_sec.decrypt_data(encrypted_data)
        if decrypted:
            info(f'   Decrypted: {decrypted.decode()}\n')
            return decrypted.decode()
        
        info(f'   ❌ Decryption failed!\n')
        return None
    
    def get_statistics(self):
        """Get security statistics"""
        stats = {
            'total_hosts': len(self.security_hosts),
            'verified_connections': len(self.verified_pairs) // 2,
            'hosts': {}
        }
        
        for name, sec in self.security_hosts.items():
            stats['hosts'][name] = {
                'verified_peers': sec.get_verified_hosts()
            }
        
        return stats
    
    def print_statistics(self):
        """Print security statistics"""
        stats = self.get_statistics()
        
        info('\n' + '=' * 60 + '\n')
        info('SECURITY STATISTICS\n')
        info('=' * 60 + '\n')
        info(f'Total secured hosts: {stats["total_hosts"]}\n')
        info(f'Verified connections: {stats["verified_connections"]}\n')
        info('\nHost Details:\n')
        
        for host, data in stats['hosts'].items():
            info(f'  {host}: verified peers = {data["verified_peers"]}\n')
        
        info('=' * 60 + '\n')


def demonstrate_security(security_mgr):
    """Demonstrate security features"""
    info('\n' + '=' * 60 + '\n')
    info('SECURITY DEMONSTRATION\n')
    info('=' * 60 + '\n')
    
    # Demo 1: HQ to HQ communication (same subnet)
    info('\n📍 DEMO 1: HQ Internal Communication (hqpc1 → hqpc2)\n')
    info('-' * 60 + '\n')
    
    # Authenticate
    if security_mgr.authenticate_hosts('hqpc1', 'hqpc2'):
        # Exchange keys
        security_mgr.exchange_session_keys('hqpc1', 'hqpc2')
        
        # Send encrypted message
        msg = "Internal HQ document: Budget 2024"
        encrypted = security_mgr.send_encrypted_message('hqpc1', 'hqpc2', msg)
        
        if encrypted:
            security_mgr.receive_encrypted_message('hqpc2', encrypted)
    
    time.sleep(1)
    
    # Demo 2: HQ to Branch communication (across subnets)
    info('\n📍 DEMO 2: Cross-Site Communication (hqpc1 → brpc1)\n')
    info('-' * 60 + '\n')
    
    if security_mgr.authenticate_hosts('hqpc1', 'brpc1'):
        security_mgr.exchange_session_keys('hqpc1', 'brpc1')
        
        msg = "Confidential: New branch policies"
        encrypted = security_mgr.send_encrypted_message('hqpc1', 'brpc1', msg)
        
        if encrypted:
            security_mgr.receive_encrypted_message('brpc1', encrypted)
    
    time.sleep(1)
    
    # Demo 3: Unauthorized access attempt
    info('\n📍 DEMO 3: Unauthorized Access Attempt (brpc2 → hqpc1 without auth)\n')
    info('-' * 60 + '\n')
    
    msg = "Attempting unauthorized access..."
    encrypted = security_mgr.send_encrypted_message('brpc2', 'hqpc1', msg)
    # This should fail because hosts aren't authenticated
    
    time.sleep(1)
    
    # Demo 4: Branch to Branch communication
    info('\n📍 DEMO 4: Branch Internal Communication (brpc1 → brpc2)\n')
    info('-' * 60 + '\n')
    
    if security_mgr.authenticate_hosts('brpc1', 'brpc2'):
        security_mgr.exchange_session_keys('brpc1', 'brpc2')
        
        msg = "Branch update: Inventory status"
        encrypted = security_mgr.send_encrypted_message('brpc1', 'brpc2', msg)
        
        if encrypted:
            security_mgr.receive_encrypted_message('brpc2', encrypted)
    
    # Print statistics
    security_mgr.print_statistics()


# ---------- Custom CLI Commands ----------
class SecurityCLI(CLI):
    """Extended CLI with security commands"""
    
    def __init__(self, mininet, security_mgr, **kwargs):
        self.security_mgr = security_mgr
        CLI.__init__(self, mininet, **kwargs)
    
    def do_authenticate(self, line):
        """Authenticate two hosts: authenticate <host1> <host2>"""
        args = line.split()
        if len(args) != 2:
            info('Usage: authenticate <host1> <host2>\n')
            return
        
        self.security_mgr.authenticate_hosts(args[0], args[1])
    
    def do_sharekey(self, line):
        """Exchange session keys: sharekey <host1> <host2>"""
        args = line.split()
        if len(args) != 2:
            info('Usage: sharekey <host1> <host2>\n')
            return
        
        self.security_mgr.exchange_session_keys(args[0], args[1])
    
    def do_encrypt(self, line):
        """Send encrypted message: encrypt <src> <dst> <message>"""
        args = line.split(maxsplit=2)
        if len(args) != 3:
            info('Usage: encrypt <src> <dst> <message>\n')
            return
        
        encrypted = self.security_mgr.send_encrypted_message(args[0], args[1], args[2])
        if encrypted:
            decrypted = self.security_mgr.receive_encrypted_message(args[1], encrypted)
    
    def do_secstats(self, line):
        """Show security statistics"""
        self.security_mgr.print_statistics()
    
    def do_revoke(self, line):
        """Revoke trust: revoke <host1> <host2>"""
        args = line.split()
        if len(args) != 2:
            info('Usage: revoke <host1> <host2>\n')
            return
        
        host1, host2 = args[0], args[1]
        
        # Revoke in security modules (one-directional trust)
        host1_sec = self.security_mgr.security_hosts.get(host1)
        host2_sec = self.security_mgr.security_hosts.get(host2)
        
        if host1_sec:
            host1_sec.revoke_host(host2)
            info(f'✅ {host1} revoked trust for {host2}\n')
        
        if host2_sec:
            host2_sec.revoke_host(host1)
            info(f'✅ {host2} revoked trust for {host1}\n')
        
        # Remove from verified_pairs (bidirectional communication prevention)
        pairs_to_remove = [
            (host1, host2),
            (host2, host1)
        ]
        
        for pair in pairs_to_remove:
            if pair in self.security_mgr.verified_pairs:
                self.security_mgr.verified_pairs.remove(pair)
                info(f'🔒 Removed verified pair: {pair[0]} → {pair[1]}\n')
        
        info(f'⚠️ Secure channel between {host1} and {host2} is now CLOSED\n')


# ---------- Run Network ----------
def run():
    """Main function to setup and run the network"""
    topo = OfficeNetwork()
    net = Mininet(topo=topo, controller=None, switch=OVSSwitch, link=TCLink, waitConnected=True)

    info('\n*** Adding Ryu controller\n')
    c0 = net.addController('c0', controller=RemoteController,
                           ip='127.0.0.1', port=6653)

    info('\n*** Starting network\n')
    net.start()

    # Wait for controller
    info('*** Waiting for controller connection...\n')
    time.sleep(3)

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

    info('✅ Network routes configured\n')

    # Initialize Security
    info('\n' + '=' * 60 + '\n')
    info('INITIALIZING SECURITY LAYER \n')
    info('=' * 60 + '\n')
    
    try:
        security_mgr = NetworkSecurityManager(net)
    except Exception as e:
        info(f'\n❌ Security initialization failed: {e}\n')
        info('Network will continue without security features\n')
        CLI(net)
        net.stop()
        return
    
    # Run security demonstration
    try:
        demonstrate_security(security_mgr)
    except Exception as e:
        info(f'\n⚠️ Security demo error: {e}\n')

    info('\n*** Network ready! Launching Security-Enhanced CLI...\n')
    info('\n📋 Available Security Commands:\n')
    info('  authenticate <host1> <host2>  - Perform Zero Trust auth\n')
    info('  sharekey <host1> <host2>      - Exchange session keys\n')
    info('  encrypt <src> <dst> <msg>     - Send encrypted message\n')
    info('  secstats                      - Show security statistics\n')
    info('  revoke <host1> <host2>        - Revoke trust\n')
    info('  pingall                       - Test connectivity\n')
    info('  exit                          - Stop network\n\n')
    
    SecurityCLI(net, security_mgr)

    info('\n*** Stopping network\n')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()