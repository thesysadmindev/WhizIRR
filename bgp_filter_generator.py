#!/usr/bin/env python3
"""
BGP Prefix Filter Generator for Mikrotik RouterOS v7
Generates prefix lists from IRR AS-SETs and creates Mikrotik commands
"""

import json
import socket
import ipaddress
import logging
import os
import re
import time
from typing import List, Dict, Set, Optional, Tuple, Union
from dataclasses import dataclass
from pathlib import Path
import argparse
import time
import hashlib
import pickle

try:
    import paramiko
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False


@dataclass
class Peer:
    asn: str
    as_set: str
    description: str


@dataclass
class RouterConfig:
    enabled: bool
    hostname: str
    username: str
    password: str
    port: int = 22


@dataclass
class Settings:
    irr_server: str
    ipv4_enabled: bool
    ipv6_enabled: bool
    output_directory: str
    max_prefix_length_ipv4: int
    max_prefix_length_ipv6: int


class IRRQueryError(Exception):
    """Exception raised for IRR query errors"""
    pass


@dataclass
class PeerState:
    """State information for a peer's prefixes"""
    ipv4_prefixes: List[str]
    ipv6_prefixes: List[str]
    last_updated: float
    prefix_hash: str


@dataclass  
class PrefixDiff:
    """Represents the differences in prefixes between runs"""
    added_ipv4: List[str]
    removed_ipv4: List[str] 
    added_ipv6: List[str]
    removed_ipv6: List[str]
    unchanged_ipv4: List[str]
    unchanged_ipv6: List[str]


class StateManager:
    """Manages state persistence for change detection"""
    
    def __init__(self, state_file: str = "bgp_filter_state.pkl"):
        self.state_file = state_file
        self.state: Dict[str, PeerState] = {}
        self.load_state()
    
    def load_state(self):
        """Load previous state from disk"""
        try:
            if os.path.exists(self.state_file):
                with open(self.state_file, 'rb') as f:
                    self.state = pickle.load(f)
                logging.info(f"Loaded state for {len(self.state)} peers from {self.state_file}")
            else:
                logging.info("No previous state found, starting fresh")
        except Exception as e:
            logging.warning(f"Failed to load state: {e}, starting fresh")
            self.state = {}
    
    def save_state(self):
        """Save current state to disk"""
        try:
            with open(self.state_file, 'wb') as f:
                pickle.dump(self.state, f)
            logging.info(f"Saved state for {len(self.state)} peers to {self.state_file}")
        except Exception as e:
            logging.error(f"Failed to save state: {e}")
    
    def get_prefix_hash(self, ipv4_prefixes: List[str], ipv6_prefixes: List[str]) -> str:
        """Generate a hash of the prefix lists for change detection"""
        # Sort prefixes to ensure consistent hashing
        combined = sorted(ipv4_prefixes) + sorted(ipv6_prefixes)
        content = '|'.join(combined)
        return hashlib.sha256(content.encode()).hexdigest()
    
    def has_changed(self, asn: str, ipv4_prefixes: List[str], ipv6_prefixes: List[str]) -> bool:
        """Check if prefixes have changed since last run"""
        new_hash = self.get_prefix_hash(ipv4_prefixes, ipv6_prefixes)
        
        if asn not in self.state:
            return True  # First time seeing this ASN
        
        return self.state[asn].prefix_hash != new_hash
    
    def update_peer_state(self, asn: str, ipv4_prefixes: List[str], ipv6_prefixes: List[str]):
        """Update the state for a peer"""
        prefix_hash = self.get_prefix_hash(ipv4_prefixes, ipv6_prefixes)
        self.state[asn] = PeerState(
            ipv4_prefixes=ipv4_prefixes.copy(),
            ipv6_prefixes=ipv6_prefixes.copy(),
            last_updated=time.time(),
            prefix_hash=prefix_hash
        )
    
    def get_previous_prefixes(self, asn: str) -> Tuple[List[str], List[str]]:
        """Get the previous prefixes for a peer"""
        if asn in self.state:
            return self.state[asn].ipv4_prefixes, self.state[asn].ipv6_prefixes
        return [], []
    
    def calculate_prefix_diff(self, asn: str, new_ipv4_prefixes: List[str], new_ipv6_prefixes: List[str]) -> PrefixDiff:
        """Calculate the differences in prefixes between current and previous state"""
        old_ipv4, old_ipv6 = self.get_previous_prefixes(asn)
        
        # Convert to sets for efficient operations
        old_ipv4_set = set(old_ipv4)
        new_ipv4_set = set(new_ipv4_prefixes)
        old_ipv6_set = set(old_ipv6)
        new_ipv6_set = set(new_ipv6_prefixes)
        
        return PrefixDiff(
            added_ipv4=list(new_ipv4_set - old_ipv4_set),
            removed_ipv4=list(old_ipv4_set - new_ipv4_set),
            added_ipv6=list(new_ipv6_set - old_ipv6_set),
            removed_ipv6=list(old_ipv6_set - new_ipv6_set),
            unchanged_ipv4=list(new_ipv4_set & old_ipv4_set),
            unchanged_ipv6=list(new_ipv6_set & old_ipv6_set)
        )


class PrefixAggregator:
    """Aggregates IP prefixes to minimize the number of entries"""
    
    @staticmethod
    def aggregate_prefixes(prefixes: List[str], family: str = 'ipv4') -> List[str]:
        """
        Aggregate a list of IP prefixes to minimize entries
        
        Args:
            prefixes: List of IP prefixes in CIDR notation
            family: Address family ('ipv4' or 'ipv6')
            
        Returns:
            List of aggregated prefixes
        """
        if not prefixes:
            return []
        
        # Parse prefixes into network objects
        networks = []
        for prefix in prefixes:
            try:
                network = ipaddress.ip_network(prefix, strict=False)
                networks.append(network)
            except ipaddress.AddressValueError:
                logging.warning(f"Invalid prefix skipped: {prefix}")
                continue
        
        if not networks:
            return []
        
        # Use ipaddress.collapse_addresses to aggregate
        collapsed = list(ipaddress.collapse_addresses(networks))
        
        # Convert back to string format
        return [str(network) for network in collapsed]


class IRRClient:
    """Client for querying IRR databases"""
    
    def __init__(self, server: str = "whois.apnic.net", port: int = 43):
        self.server = server
        self.port = port
        self.socket: Optional[socket.socket] = None
        
        # Server-specific query formats
        self.server_config = self._get_server_config(server)
    
    def _get_server_config(self, server: str) -> Dict[str, str]:
        """Get server-specific query configuration"""
        configs = {
            "whois.radb.net": {
                "as_set_query": "{as_set}",  # Direct query
                "route_query": "-i origin {asn}",  # Standard whois format
                "supports_gii": False
            },
            "whois.apnic.net": {
                "as_set_query": "!i{as_set}",  # IRRd format
                "route_query": "!g{asn}",  # IRRd format
                "supports_gii": True
            },
            "whois.ripe.net": {
                "as_set_query": "{as_set}",  # Direct query
                "route_query": "-T route -i origin {asn}",  # RIPE format
                "supports_gii": False
            },
            "whois.arin.net": {
                "as_set_query": "{as_set}",  # Direct query
                "route_query": "-T route -i origin {asn}",  # Standard format
                "supports_gii": False
            }
        }
        
        # Default to RADB format for unknown servers
        return configs.get(server.lower(), configs["whois.radb.net"])
        
    def connect(self):
        """Connect to the IRR server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(30)
            self.socket.connect((self.server, self.port))
            logging.info(f"Connected to IRR server {self.server}:{self.port}")
        except Exception as e:
            raise IRRQueryError(f"Failed to connect to IRR server: {e}")
    
    def disconnect(self):
        """Disconnect from the IRR server"""
        if self.socket:
            self.socket.close()
            self.socket = None
    
    def query(self, query: str) -> str:
        """
        Send a query to the IRR server
        
        Args:
            query: The query string
            
        Returns:
            Response from the server
        """
        # Always use a fresh connection for each query to avoid socket state issues
        self.disconnect()
        self.connect()
        
        if not self.socket:
            raise IRRQueryError("Failed to establish connection")
        
        try:
            # Send query
            self.socket.send(f"{query}\n".encode('utf-8'))
            
            # Receive response
            response = b""
            start_time = time.time()
            while time.time() - start_time < 10:  # 10 second timeout
                try:
                    chunk = self.socket.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    # Check if we've received the complete response
                    if len(chunk) < 4096:
                        break
                except socket.timeout:
                    break
            
            self.disconnect()  # Close connection after each query
            return response.decode('utf-8', errors='ignore')
        
        except Exception as e:
            self.disconnect()
            raise IRRQueryError(f"Query failed: {e}")
    
    def get_as_set_members(self, as_set: str) -> Set[str]:
        """
        Get members of an AS-SET recursively
        
        Args:
            as_set: The AS-SET name
            
        Returns:
            Set of AS numbers and nested AS-SETs
        """
        logging.info(f"Querying AS-SET: {as_set}")
        
        try:
            # Use server-specific query format
            query = self.server_config["as_set_query"].format(as_set=as_set)
            response = self.query(query)
            
            members = set()
            in_members_section = False
            
            for line in response.split('\n'):
                line = line.strip()
                
                # Skip comments and headers
                if line.startswith('%') or line.startswith('#'):
                    continue
                
                if line.startswith('members:'):
                    in_members_section = True
                    # Extract members from the same line
                    member_part = line[8:].strip()
                    if member_part:
                        # Handle comma-separated values
                        for member in member_part.replace(',', ' ').split():
                            member = member.strip()
                            if member:
                                members.add(member)
                
                elif in_members_section and line and (line.startswith(' ') or line.startswith('\t')):
                    # Continuation line
                    for member in line.replace(',', ' ').split():
                        member = member.strip()
                        if member:
                            members.add(member)
                
                elif in_members_section and line and not line.startswith(' ') and not line.startswith('\t'):
                    # End of members section
                    break
            
            logging.info(f"Found {len(members)} members for {as_set}: {members}")
            return members
        
        except Exception as e:
            logging.error(f"Failed to query AS-SET {as_set}: {e}")
            return set()
    
    def _is_valid_prefix(self, prefix: str) -> bool:
        """
        Validate if a string looks like a valid IP prefix
        
        Args:
            prefix: String to validate
            
        Returns:
            True if it looks like a valid prefix
        """
        if not prefix or not isinstance(prefix, str):
            return False
        
        # Must contain a slash for CIDR notation
        if '/' not in prefix:
            return False
        
        # Basic format check: should be IP/mask
        parts = prefix.split('/')
        if len(parts) != 2:
            return False
        
        ip_part, mask_part = parts
        
        # IP part should not be empty and should contain dots or colons
        if not ip_part or (('.' not in ip_part) and (':' not in ip_part)):
            return False
        
        # Mask part should be numeric
        if not mask_part.isdigit():
            return False
        
        # Additional sanity checks
        mask = int(mask_part)
        if ':' in ip_part:  # IPv6
            if mask > 128:
                return False
        else:  # IPv4
            if mask > 32:
                return False
        
        return True

    def get_as_prefixes(self, asn: str) -> Tuple[List[str], List[str]]:
        """
        Get route prefixes announced by an AS
        
        Args:
            asn: AS number (e.g., 'AS65001')
            
        Returns:
            Tuple of (IPv4 prefixes, IPv6 prefixes)
        """
        logging.info(f"Querying prefixes for AS: {asn}")
        
        ipv4_prefixes = []
        ipv6_prefixes = []
        
        try:
            # Use server-specific query format
            query = self.server_config["route_query"].format(asn=asn)
            logging.debug(f"Executing query: {query}")
            response = self.query(query)
            logging.debug(f"Response length: {len(response)} characters")
            
            lines = response.split('\n')
            logging.debug(f"Processing {len(lines)} lines")
            
            for i, line in enumerate(lines):
                line = line.strip()
                
                # Skip empty lines, comments and headers
                if not line or line.startswith('%') or line.startswith('#'):
                    continue
                
                # Look for route objects
                if line.startswith('route:'):
                    prefix = line[6:].strip()
                    logging.debug(f"Found route line {i+1}: '{prefix}'")
                    if self._is_valid_prefix(prefix):
                        try:
                            network = ipaddress.ip_network(prefix, strict=False)
                            if isinstance(network, ipaddress.IPv4Network):
                                ipv4_prefixes.append(str(network))
                                logging.debug(f"Added IPv4 prefix: {network}")
                            elif isinstance(network, ipaddress.IPv6Network):
                                ipv6_prefixes.append(str(network))
                                logging.debug(f"Added IPv6 prefix: {network}")
                        except ipaddress.AddressValueError as e:
                            logging.warning(f"Invalid route prefix '{prefix}': {e}")
                    else:
                        logging.debug(f"Skipping invalid prefix format: '{prefix}'")
                
                elif line.startswith('route6:'):
                    prefix = line[7:].strip()
                    logging.debug(f"Found route6 line {i+1}: '{prefix}'")
                    if self._is_valid_prefix(prefix):
                        try:
                            network = ipaddress.ip_network(prefix, strict=False)
                            if isinstance(network, ipaddress.IPv6Network):
                                ipv6_prefixes.append(str(network))
                                logging.debug(f"Added IPv6 prefix: {network}")
                        except ipaddress.AddressValueError as e:
                            logging.warning(f"Invalid route6 prefix '{prefix}': {e}")
                    else:
                        logging.debug(f"Skipping invalid prefix format: '{prefix}'")
                
                # For IRRd format (like APNIC), routes are on separate lines
                elif self.server_config.get("supports_gii", False):
                    # Try to parse space-separated prefixes (IRRd format)
                    for prefix_candidate in line.split():
                        if self._is_valid_prefix(prefix_candidate):
                            try:
                                network = ipaddress.ip_network(prefix_candidate, strict=False)
                                if isinstance(network, ipaddress.IPv4Network):
                                    ipv4_prefixes.append(str(network))
                                    logging.debug(f"Added IPv4 prefix from IRRd format: {network}")
                                elif isinstance(network, ipaddress.IPv6Network):
                                    ipv6_prefixes.append(str(network))
                                    logging.debug(f"Added IPv6 prefix from IRRd format: {network}")
                            except ipaddress.AddressValueError:
                                pass  # Ignore invalid prefixes
            
            logging.info(f"Found {len(ipv4_prefixes)} IPv4 and {len(ipv6_prefixes)} IPv6 prefixes for {asn}")
            if ipv4_prefixes:
                logging.debug(f"IPv4 prefixes: {ipv4_prefixes}")
            if ipv6_prefixes:
                logging.debug(f"IPv6 prefixes: {ipv6_prefixes}")
            
        except Exception as e:
            logging.error(f"Failed to query prefixes for {asn}: {e}")
        
        return ipv4_prefixes, ipv6_prefixes


class Config:
    """Configuration container"""
    def __init__(self):
        self.peers: List[Peer] = []
        self.router: RouterConfig = RouterConfig(False, "", "", "", 22)
        self.settings: Settings = Settings("", False, False, "", 24, 48)


class BGPPrefixGenerator:
    """Main class for generating BGP prefix filters"""
    
    def __init__(self, config_file: str = "config.json", force_full: bool = False):
        self.config = self._load_config(config_file)
        self.irr_client = IRRClient(self.config.settings.irr_server)
        self.aggregator = PrefixAggregator()
        self.state_manager = StateManager()
        self.force_full = force_full
        
        # Create output directory
        Path(self.config.settings.output_directory).mkdir(parents=True, exist_ok=True)
    
    def _load_config(self, config_file: str) -> 'Config':
        """Load configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                data = json.load(f)
            
            peers = [Peer(**peer) for peer in data['peers']]
            router = RouterConfig(**data['router'])
            settings = Settings(**data['settings'])
            
            # Create a configuration object
            config = Config()
            config.peers = peers
            config.router = router
            config.settings = settings
            
            return config
            
        except Exception as e:
            raise Exception(f"Failed to load configuration: {e}")
    
    def _expand_as_set_recursively(self, as_set: str, visited: Optional[Set[str]] = None) -> Set[str]:
        """
        Recursively expand an AS-SET to get all AS numbers
        
        Args:
            as_set: The AS-SET to expand
            visited: Set of already visited AS-SETs to prevent loops
            
        Returns:
            Set of AS numbers
        """
        if visited is None:
            visited = set()
        
        if as_set in visited:
            logging.warning(f"Loop detected, skipping {as_set}")
            return set()
        
        visited.add(as_set)
        as_numbers = set()
        
        logging.debug(f"Expanding AS-SET: {as_set}")
        members = self.irr_client.get_as_set_members(as_set)
        logging.debug(f"Members found: {members}")
        
        for member in members:
            member = member.strip()
            if not member:
                continue
                
            logging.debug(f"Processing member: {member}")
            
            # Check if this is an AS number (AS followed by digits)
            if re.match(r'^AS\d+$', member):
                logging.debug(f"Adding AS number: {member}")
                as_numbers.add(member)
            
            # Check if this is an AS-SET (various formats)
            elif (member.startswith('AS-') or 
                  member.startswith('AS_') or 
                  re.match(r'^AS\d+:', member) or  # Handle AS123:AS-NAME format
                  member.startswith('AS:')):
                
                logging.info(f"Recursively expanding nested AS-SET: {member}")
                nested_as_numbers = self._expand_as_set_recursively(member, visited.copy())
                as_numbers.update(nested_as_numbers)
                logging.debug(f"Added {len(nested_as_numbers)} AS numbers from {member}")
            
            else:
                logging.debug(f"Skipping unrecognized member format: {member}")
        
        logging.info(f"Total AS numbers found for {as_set}: {len(as_numbers)}")
        if as_numbers:
            logging.debug(f"AS numbers: {sorted(as_numbers)}")
        
        return as_numbers
    
    def generate_prefix_list(self, peer: Peer) -> Tuple[List[str], List[str]]:
        """
        Generate prefix list for a peer
        
        Args:
            peer: Peer configuration
            
        Returns:
            Tuple of (IPv4 prefixes, IPv6 prefixes)
        """
        logging.info(f"Processing peer: {peer.description} ({peer.asn})")
        
        # Expand AS-SET to get all AS numbers
        as_numbers = self._expand_as_set_recursively(peer.as_set)
        as_numbers.add(peer.asn)  # Include the peer's own ASN
        
        logging.info(f"Found {len(as_numbers)} AS numbers for {peer.as_set}")
        
        all_ipv4_prefixes = []
        all_ipv6_prefixes = []
        
        # Get prefixes for each AS number
        for asn in as_numbers:
            ipv4_prefixes, ipv6_prefixes = self.irr_client.get_as_prefixes(asn)
            all_ipv4_prefixes.extend(ipv4_prefixes)
            all_ipv6_prefixes.extend(ipv6_prefixes)
            
            # Add a small delay to avoid overwhelming the server
            time.sleep(0.1)
        
        # Filter prefixes by maximum length
        if self.config.settings.ipv4_enabled:
            all_ipv4_prefixes = [
                prefix for prefix in all_ipv4_prefixes
                if int(prefix.split('/')[-1]) <= self.config.settings.max_prefix_length_ipv4
            ]
        
        if self.config.settings.ipv6_enabled:
            all_ipv6_prefixes = [
                prefix for prefix in all_ipv6_prefixes
                if int(prefix.split('/')[-1]) <= self.config.settings.max_prefix_length_ipv6
            ]
        
        # Aggregate prefixes
        if all_ipv4_prefixes:
            all_ipv4_prefixes = self.aggregator.aggregate_prefixes(all_ipv4_prefixes, 'ipv4')
        
        if all_ipv6_prefixes:
            all_ipv6_prefixes = self.aggregator.aggregate_prefixes(all_ipv6_prefixes, 'ipv6')
        
        logging.info(f"Final result: {len(all_ipv4_prefixes)} IPv4 and {len(all_ipv6_prefixes)} IPv6 prefixes")
        
        return all_ipv4_prefixes, all_ipv6_prefixes
    
    def generate_mikrotik_commands(self, peer: Peer, ipv4_prefixes: List[str], ipv6_prefixes: List[str]) -> List[str]:
        """
        Generate Mikrotik RouterOS v7 commands for prefix lists
        
        Args:
            peer: Peer configuration
            ipv4_prefixes: List of IPv4 prefixes
            ipv6_prefixes: List of IPv6 prefixes
            
        Returns:
            List of RouterOS commands
        """
        commands = []
        
        # Extract AS number from ASN (remove 'AS' prefix)
        asn = peer.asn.replace('AS', '')
        
        # Generate IPv4 prefix list
        if ipv4_prefixes and self.config.settings.ipv4_enabled:
            filter_name = f"IMPORT-AS{asn}-V4"
            commands.append(f"# IPv4 prefix list for {peer.description} ({peer.asn})")
            
            # Delete existing filter rules for this chain
            commands.append(f'/routing filter rule remove [find chain="{filter_name}"]')
            
            for prefix in ipv4_prefixes:
                commands.append(f'/routing filter rule add chain="{filter_name}" rule="if (dst in {prefix} && dst-len <= 24) {{accept}}"')
            
            # Add default deny rule
            commands.append(f'/routing filter rule add chain="{filter_name}" rule="reject"')
            commands.append("")
        
        # Generate IPv6 prefix list
        if ipv6_prefixes and self.config.settings.ipv6_enabled:
            filter_name = f"IMPORT-AS{asn}-V6"
            commands.append(f"# IPv6 prefix list for {peer.description} ({peer.asn})")
            
            # Delete existing filter rules for this chain
            commands.append(f'/routing filter rule remove [find chain="{filter_name}"]')
            
            for prefix in ipv6_prefixes:
                commands.append(f'/routing filter rule add chain="{filter_name}" rule="if (dst in {prefix} && dst-len <= 48) {{accept}}"')
            
            # Add default deny rule
            commands.append(f'/routing filter rule add chain="{filter_name}" rule="reject"')
            commands.append("")
        
        return commands
    
    def generate_mikrotik_commands_differential(self, peer: Peer, prefix_diff: PrefixDiff) -> List[str]:
        """
        Generate Mikrotik RouterOS v7 commands for differential prefix updates
        
        Args:
            peer: Peer configuration
            prefix_diff: The differences in prefixes (added/removed/unchanged)
            
        Returns:
            List of RouterOS commands for incremental changes only
        """
        commands = []
        
        # Extract AS number from ASN (remove 'AS' prefix)
        asn = peer.asn.replace('AS', '')
        
        # Generate differential IPv4 commands
        if (prefix_diff.added_ipv4 or prefix_diff.removed_ipv4) and self.config.settings.ipv4_enabled:
            filter_name = f"IMPORT-AS{asn}-V4"
            commands.append(f"# IPv4 prefix changes for {peer.description} ({peer.asn})")
            
            # Remove deleted prefixes
            for prefix in prefix_diff.removed_ipv4:
                commands.append(f'/routing filter rule remove [find chain="{filter_name}" && rule~"dst in {prefix}"]')
            
            # Add new prefixes (insert before the reject rule)
            for prefix in prefix_diff.added_ipv4:
                commands.append(f'/routing filter rule add chain="{filter_name}" place-before=[find chain="{filter_name}" && rule="reject"] rule="if (dst in {prefix} && dst-len <= 24) {{accept}}"')
            
            commands.append("")
        
        # Generate differential IPv6 commands  
        if (prefix_diff.added_ipv6 or prefix_diff.removed_ipv6) and self.config.settings.ipv6_enabled:
            filter_name = f"IMPORT-AS{asn}-V6"
            commands.append(f"# IPv6 prefix changes for {peer.description} ({peer.asn})")
            
            # Remove deleted prefixes
            for prefix in prefix_diff.removed_ipv6:
                commands.append(f'/routing filter rule remove [find chain="{filter_name}" && rule~"dst in {prefix}"]')
            
            # Add new prefixes (insert before the reject rule)
            for prefix in prefix_diff.added_ipv6:
                commands.append(f'/routing filter rule add chain="{filter_name}" place-before=[find chain="{filter_name}" && rule="reject"] rule="if (dst in {prefix} && dst-len <= 48) {{accept}}"')
            
            commands.append("")
        
        return commands
    
    def send_commands_to_router(self, commands: List[str]) -> bool:
        """
        Send commands to Mikrotik router via SSH
        
        Args:
            commands: List of RouterOS commands
            
        Returns:
            True if successful, False otherwise
        """
        if not SSH_AVAILABLE:
            logging.error("Paramiko is not installed. Cannot connect to router via SSH.")
            return False
        
        if not self.config.router.enabled:
            logging.info("Router SSH is disabled in configuration")
            return False
        
        try:
            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect to router
            logging.info(f"Connecting to router {self.config.router.hostname}...")
            ssh.connect(
                hostname=self.config.router.hostname,
                port=self.config.router.port,
                username=self.config.router.username,
                password=self.config.router.password,
                timeout=30
            )
            
            # Execute commands
            for i, command in enumerate(commands):
                if command.strip() and not command.startswith('#'):
                    logging.debug(f"Executing command {i+1}: {command}")
                    stdin, stdout, stderr = ssh.exec_command(command)
                    
                    # Get output and error
                    output = stdout.read().decode().strip()
                    error = stderr.read().decode().strip()
                    
                    # Check for errors
                    if error:
                        logging.error(f"Command {i+1} failed: {command}")
                        logging.error(f"Error: {error}")
                        return False
                    elif output:
                        logging.debug(f"Command {i+1} output: {output}")
            
            ssh.close()
            logging.info("Commands sent to router successfully")
            return True
            
        except Exception as e:
            logging.error(f"Failed to send commands to router: {e}")
            return False
    
    def save_commands_to_file(self, peer: Peer, commands: List[str]):
        """
        Save commands to a text file
        
        Args:
            peer: Peer configuration
            commands: List of RouterOS commands
        """
        asn = peer.asn.replace('AS', '')
        filename = f"prefix-filter-{asn}.rsc"
        filepath = Path(self.config.settings.output_directory) / filename
        
        try:
            with open(filepath, 'w') as f:
                f.write(f"# BGP Prefix Filter for {peer.description} ({peer.asn})\n")
                f.write(f"# AS-SET: {peer.as_set}\n")
                f.write(f"# Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                for command in commands:
                    f.write(f"{command}\n")
            
            logging.info(f"Commands saved to: {filepath}")
            
        except Exception as e:
            logging.error(f"Failed to save commands to file: {e}")
    
    def process_all_peers(self):
        """Process all peers and generate prefix filters"""
        logging.info("Starting BGP prefix filter generation")
        
        changed_peers = []
        unchanged_peers = []
        
        try:
            self.irr_client.connect()
            
            for peer in self.config.peers:
                try:
                    # Generate prefix list
                    ipv4_prefixes, ipv6_prefixes = self.generate_prefix_list(peer)
                    
                    # Check if prefixes have changed OR if full generation is forced
                    has_changes = self.state_manager.has_changed(peer.asn, ipv4_prefixes, ipv6_prefixes)
                    should_process = has_changes or self.force_full
                    
                    if should_process:
                        if has_changes:
                            changed_peers.append(peer.asn)
                            logging.info(f"Changes detected for {peer.asn}")
                        else:
                            # No changes but --full is specified
                            changed_peers.append(peer.asn)
                            logging.info(f"No changes detected for {peer.asn}, but generating full config due to --full flag")
                        
                        # Check if this is a completely new peer (no previous state) BEFORE updating state
                        old_ipv4, old_ipv6 = self.state_manager.get_previous_prefixes(peer.asn)
                        is_new_peer = not old_ipv4 and not old_ipv6
                        
                        # Calculate the differences (only needed if not forcing full)
                        if has_changes and not self.force_full:
                            prefix_diff = self.state_manager.calculate_prefix_diff(peer.asn, ipv4_prefixes, ipv6_prefixes)
                            
                            # Log the changes for visibility
                            if prefix_diff.added_ipv4:
                                logging.info(f"  Added IPv4 prefixes: {len(prefix_diff.added_ipv4)}")
                            if prefix_diff.removed_ipv4:
                                logging.info(f"  Removed IPv4 prefixes: {len(prefix_diff.removed_ipv4)}")
                            if prefix_diff.added_ipv6:
                                logging.info(f"  Added IPv6 prefixes: {len(prefix_diff.added_ipv6)}")
                            if prefix_diff.removed_ipv6:
                                logging.info(f"  Removed IPv6 prefixes: {len(prefix_diff.removed_ipv6)}")
                        
                        # Update state
                        self.state_manager.update_peer_state(peer.asn, ipv4_prefixes, ipv6_prefixes)
                        
                        # Generate commands - use full rebuild for new peers, when forced, or differential for existing ones
                        if is_new_peer or self.force_full:
                            # New peer, first run, or force full generation - generate full commands
                            if self.force_full:
                                logging.info(f"  Generating full filter config (--full flag specified)")
                            else:
                                logging.info(f"  Generating full filter config (new peer)")
                            commands = self.generate_mikrotik_commands(peer, ipv4_prefixes, ipv6_prefixes)
                        else:
                            # Existing peer with changes - generate differential commands
                            logging.info(f"  Generating differential updates only")
                            commands = self.generate_mikrotik_commands_differential(peer, prefix_diff)
                        
                        if commands:
                            # Try to send to router first
                            if self.config.router.enabled:
                                success = self.send_commands_to_router(commands)
                                if not success:
                                    logging.warning("Failed to send to router, saving to file instead")
                                    self.save_commands_to_file(peer, commands)
                            else:
                                # Save to file
                                self.save_commands_to_file(peer, commands)
                        else:
                            logging.info(f"No changes to apply for peer {peer.asn}")
                    else:
                        unchanged_peers.append(peer.asn)
                        logging.info(f"No changes detected for {peer.asn}, skipping update")
                
                except Exception as e:
                    logging.error(f"Failed to process peer {peer.asn}: {e}")
                    continue
        
        finally:
            self.irr_client.disconnect()
            # Save state after all processing is complete
            self.state_manager.save_state()
        
        logging.info(f"BGP prefix filter generation completed")
        logging.info(f"Changed peers: {len(changed_peers)} - {', '.join(changed_peers) if changed_peers else 'None'}")
        logging.info(f"Unchanged peers: {len(unchanged_peers)} - {', '.join(unchanged_peers) if unchanged_peers else 'None'}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="BGP Prefix Filter Generator for Mikrotik RouterOS v7")
    parser.add_argument("-c", "--config", default="config.json", help="Configuration file path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--full", action="store_true", help="Generate full filter sets instead of differential updates")
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.INFO
    if args.debug:
        log_level = logging.DEBUG
    elif args.verbose:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('bgp_filter_generator.log')
        ]
    )
    
    try:
        generator = BGPPrefixGenerator(args.config, force_full=args.full)
        generator.process_all_peers()
        
    except Exception as e:
        logging.error(f"Application error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
