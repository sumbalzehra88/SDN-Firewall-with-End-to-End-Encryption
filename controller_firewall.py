#!/usr/bin/env python3
"""
Ryu OpenFlow 1.3 Firewall Controller with SECURITY INTEGRATION
"""

import json
import os
import ipaddress
import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, ether_types


POLICY_FILE = "policy.json"

class SecureFirewallController(app_manager.RyuApp):
    """
    Enhanced firewall controller with security features
    Member 2: Firewall logic
    Member 3: Security verification
    """
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SecureFirewallController, self).__init__(*args, **kwargs)
        self.logger.info("🚀 Starting Secure Firewall Controller...")
        self.logger.info("🔐 Security Layer: ACTIVE (Member 3)")
        
        # Firewall policies (Member 2)
        self.policies = {"allow": [], "block": []}
        self._load_policy()
        
        # Security features (Member 3)
        self.verified_hosts = {}  # IP -> verification status
        self.encrypted_flows = set()  # Track encrypted flows
        self.intrusion_attempts = []  # Log unauthorized attempts
        
        # Statistics
        self.stats = {
            'allowed_flows': 0,
            'blocked_flows': 0,
            'unverified_attempts': 0,
            'encrypted_packets': 0
        }

    def _load_policy(self):
        """Load firewall policy from policy.json"""
        if not os.path.exists(POLICY_FILE):
            self.logger.warning(f"⚠️ Policy file {POLICY_FILE} not found, using defaults")
            # Default allow all for testing
            self.policies = {
                "allow": [
                    {"src": "10.0.1.0/24", "dst": "10.0.2.0/24"},
                    {"src": "10.0.2.0/24", "dst": "10.0.1.0/24"},
                    {"src": "10.0.1.0/24", "dst": "10.0.1.0/24"},
                    {"src": "10.0.2.0/24", "dst": "10.0.2.0/24"}
                ],
                "block": []
            }
            return

        try:
            with open(POLICY_FILE, "r") as f:
                self.policies = json.load(f)
            self.logger.info(f"✅ Loaded policy: {self.policies}")
        except Exception as e:
            self.logger.error(f"⚠️ Error reading policy file: {e}")

    def _add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match, instructions=inst
        )
        datapath.send_msg(mod)

    def _ip_in_policy(self, ip, entry_ip):
        """Check if IP matches a policy entry (supports exact or subnet)"""
        try:
            if "/" in entry_ip:
                return ipaddress.ip_address(ip) in ipaddress.ip_network(entry_ip, strict=False)
            else:
                return ip == entry_ip
        except Exception:
            return False

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)
        self.logger.info(f"🔌 Switch {datapath.id} connected")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Handle ARP normally
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self._flood_packet(msg)
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            return

        src_ip, dst_ip = ip_pkt.src, ip_pkt.dst
        
        # ========== SECURITY CHECKS (Member 3) ==========
        
        # Check 1: Zero Trust Verification
        if not self._is_host_verified(src_ip):
            self.logger.warning(f"🔐 UNVERIFIED HOST: {src_ip} → {dst_ip}")
            self.stats['unverified_attempts'] += 1
            self._log_intrusion_attempt(src_ip, dst_ip, "Unverified host")
            
            # In production, block here. For demo, we log and allow
            # return  # Uncomment to actually block unverified hosts
        
        # Check 2: Detect encrypted traffic
        # In real implementation, check packet payload for encryption markers
        is_encrypted = self._is_traffic_encrypted(pkt)
        if is_encrypted:
            self.logger.info(f"🔒 ENCRYPTED: {src_ip} → {dst_ip}")
            self.stats['encrypted_packets'] += 1
            self.encrypted_flows.add((src_ip, dst_ip))
        else:
            self.logger.info(f"📡 PLAINTEXT: {src_ip} → {dst_ip}")
        
        # ========== FIREWALL CHECKS (Member 2) ==========
        
        # Check policies
        allowed = any(
            self._ip_in_policy(src_ip, a["src"]) and self._ip_in_policy(dst_ip, a["dst"])
            for a in self.policies.get("allow", [])
        )
        blocked = any(
            self._ip_in_policy(src_ip, b["src"]) and self._ip_in_policy(dst_ip, b["dst"])
            for b in self.policies.get("block", [])
        )

        if blocked:
            self.logger.info(f"🚫 BLOCKED by policy: {src_ip} → {dst_ip}")
            self.stats['blocked_flows'] += 1
            self._install_block_flow(datapath, src_ip, dst_ip)
            self._log_intrusion_attempt(src_ip, dst_ip, "Blocked by policy")
            return

        # Allow packet
        if allowed:
            self.logger.info(f"✅ ALLOWED by policy: {src_ip} → {dst_ip}")
        else:
            self.logger.info(f"⚠️ ALLOWED by default: {src_ip} → {dst_ip}")
        
        self.stats['allowed_flows'] += 1
        self._install_allow_flow(datapath, src_ip, dst_ip)
        self._flood_packet(msg)

    # ========== SECURITY FUNCTIONS (Member 3) ==========
    
    def _is_host_verified(self, ip):
        """
        Check if host passed Zero Trust verification
        In production, integrate with SecureHost verification
        For demo, auto-verify known subnets
        """
        # Auto-verify hosts in known subnets
        try:
            if ipaddress.ip_address(ip) in ipaddress.ip_network('10.0.1.0/24'):
                return True
            if ipaddress.ip_address(ip) in ipaddress.ip_network('10.0.2.0/24'):
                return True
        except:
            pass
        
        return ip in self.verified_hosts
    
    def verify_host(self, ip):
        """Add host to verified registry"""
        self.verified_hosts[ip] = {
            'verified_at': time.time(),
            'status': 'trusted'
        }
        self.logger.info(f"✅ Host verified: {ip}")
    
    def _is_traffic_encrypted(self, pkt):
        """
        Detect if traffic is encrypted
        Check for Fernet token patterns
        """
        try:
            # Get IP packet
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if not ip_pkt:
                return False
            
            # Get raw packet data
            if hasattr(pkt, 'data'):
                payload = bytes(pkt.data) if pkt.data else b''
                
                if len(payload) > 20:
                    # Check for Fernet base64 pattern (gAAAAA or gAAAAAB)
                    try:
                        payload_str = payload.decode('utf-8', errors='ignore')
                        if 'gAAAAA' in payload_str or 'gAAAAAB' in payload_str:
                            return True
                    except:
                        pass
                    
                    # High entropy check (encrypted data has random-looking bytes)
                    if len(payload) > 50:
                        unique = len(set(payload[:50]))
                        if unique > 40:  # More than 40 unique bytes in first 50
                            return True
            
            return False
        except Exception as e:
            return False
    
    def _log_intrusion_attempt(self, src_ip, dst_ip, reason):
        """Log potential intrusion attempt"""
        attempt = {
            'timestamp': time.time(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'reason': reason
        }
        self.intrusion_attempts.append(attempt)
        
        # Keep only last 100 attempts
        if len(self.intrusion_attempts) > 100:
            self.intrusion_attempts.pop(0)
    
    def print_security_statistics(self):
        """Print security statistics"""
        self.logger.info("\n" + "=" * 60)
        self.logger.info("SECURITY STATISTICS (Member 3)")
        self.logger.info("=" * 60)
        self.logger.info(f"✅ Allowed flows:        {self.stats['allowed_flows']}")
        self.logger.info(f"❌ Blocked flows:        {self.stats['blocked_flows']}")
        self.logger.info(f"🔐 Unverified attempts:  {self.stats['unverified_attempts']}")
        self.logger.info(f"🔒 Encrypted packets:    {self.stats['encrypted_packets']}")
        self.logger.info(f"📊 Verified hosts:       {len(self.verified_hosts)}")
        self.logger.info(f"🚨 Intrusion attempts:   {len(self.intrusion_attempts)}")
        self.logger.info(f"🔐 Encrypted flows:      {len(self.encrypted_flows)}")
        self.logger.info("=" * 60)

    # ========== FIREWALL FUNCTIONS (Member 2) ==========
    
    def _install_allow_flow(self, datapath, src_ip, dst_ip):
        """Allow packet flow"""
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
        actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_NORMAL)]
        self._add_flow(datapath, 10, match, actions)

    def _install_block_flow(self, datapath, src_ip, dst_ip):
        """Block packet flow"""
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
        actions = []  # drop
        self._add_flow(datapath, 20, match, actions)

    def _flood_packet(self, msg):
        """Send packet out all ports"""
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=msg.match['in_port'],
            actions=[parser.OFPActionOutput(ofproto.OFPP_FLOOD)],
            data=msg.data,
        )
        datapath.send_msg(out)


# Optional: Print stats periodically
def stats_printer(app):
    """Background thread to print stats every 30 seconds"""
    import threading
    def print_stats():
        while True:
            time.sleep(30)
            app.print_security_statistics()
    
    thread = threading.Thread(target=print_stats, daemon=True)
    thread.start()
