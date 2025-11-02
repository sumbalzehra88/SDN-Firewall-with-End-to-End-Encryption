#!/usr/bin/env python3
# controller_firewall.py
# Ryu OpenFlow 1.3 Firewall Controller with subnet + allow-most support

import json
import os
import ipaddress
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, ether_types


POLICY_FILE = "policy.json"  # Must be in same directory as this script

class SimpleFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleFirewall, self).__init__(*args, **kwargs)
        self.logger.info("🚀 Starting SimpleFirewall Ryu app...")
        self.policies = {"allow": [], "block": []}
        self._load_policy()

    def _load_policy(self):
        """Load firewall policy from policy.json"""
        if not os.path.exists(POLICY_FILE):
            self.logger.error(f"❌ Policy file {POLICY_FILE} not found.")
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
        self.logger.info(f"📡 Packet {src_ip} → {dst_ip}")

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
            self.logger.info(f"🚫 Blocked {src_ip} → {dst_ip}")
            self._install_block_flow(datapath, src_ip, dst_ip)
            return

        # Allow if explicitly allowed or by default
        if allowed:
            self.logger.info(f"✅ Allowed {src_ip} → {dst_ip} (explicit policy)")
        else:
            self.logger.info(f"⚠️ No explicit policy for {src_ip} → {dst_ip}, allowing by default")

        self._install_allow_flow(datapath, src_ip, dst_ip)
        self._flood_packet(msg)

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

