# WhizIRR BGP Prefix Filter Generator for Mikrotik RouterOS v7

This Python script generates BGP prefix filters for Mikrotik RouterOS v7 based on IRR AS-SETs. It queries the IRR database, expands AS-SETs recursively, aggregates prefixes, and generates RouterOS commands.

## Features

- Query IRR database for AS-SET expansion
- Recursive AS-SET expansion to find all member AS numbers
- Prefix aggregation to minimize filter entries
- Generate Mikrotik RouterOS v7 prefix filter commands
- Support for both IPv4 and IPv6 prefixes
- Optional SSH deployment to router
- Configurable maximum prefix lengths
- Output to files if SSH is not available

## Requirements

- Linux operating system
- Python 3.7+
- paramiko (for SSH functionality, optional)

## Installation

1. Clone or download this repository
2. Install dependencies:
   ```bash
   pip3 install -r requirements.txt
   ```

## Configuration

Edit the `config.json` file to configure your peers and settings:

```json
{
  "peers": [
    {
      "asn": "AS65001",
      "as_set": "AS-EXAMPLE",
      "description": "Example Peer"
    }
  ],
  "router": {
    "enabled": false,
    "hostname": "192.168.1.1",
    "username": "admin",
    "password": "",
    "port": 22
  },
  "settings": {
    "irr_server": "whois.apnic.net",
    "ipv4_enabled": true,
    "ipv6_enabled": true,
    "output_directory": "./output",
    "max_prefix_length_ipv4": 24,
    "max_prefix_length_ipv6": 48
  }
}
```

### Configuration Options

#### Peers
- `asn`: The AS number of the peer (e.g., "AS65001")
- `as_set`: The AS-SET to expand (e.g., "AS-EXAMPLE")
- `description`: Human-readable description of the peer

#### Router (SSH Configuration)
- `enabled`: Set to true to enable SSH deployment
- `hostname`: Router IP address or hostname
- `username`: SSH username
- `password`: SSH password
- `port`: SSH port (default: 22)

#### Settings
- `irr_server`: IRR server to query (default: "whois.apnic.net")
- `ipv4_enabled`: Enable IPv4 prefix generation
- `ipv6_enabled`: Enable IPv6 prefix generation
- `output_directory`: Directory for output files
- `max_prefix_length_ipv4`: Maximum IPv4 prefix length to include
- `max_prefix_length_ipv6`: Maximum IPv6 prefix length to include

## Usage

Run the script with default configuration:
```bash
python3 bgp_filter_generator.py
```

Use a custom configuration file:
```bash
python3 bgp_filter_generator.py -c custom_config.json
```

Generate full filter sets (force complete regeneration):
```bash
python3 bgp_filter_generator.py --full
```

Enable verbose logging:
```bash
python3 bgp_filter_generator.py -v
```

Enable debug logging:
```bash
python3 bgp_filter_generator.py --debug
```

Combine options:
```bash
python3 bgp_filter_generator.py --full --debug -c custom_config.json
```

### Command Line Arguments

- `--config`, `-c`: Specify custom configuration file path
- `--full`: Force generation of complete filter sets for all peers, regardless of whether changes are detected
- `--verbose`, `-v`: Enable verbose logging
- `--debug`: Enable debug logging with detailed information
- `--help`, `-h`: Show help message and available options

### Generation Modes

**Differential Mode (Default)**: The script tracks prefix changes and only generates commands for:
- New peers (full filter set on first run)
- Peers with detected prefix changes (differential updates)

**Full Mode (--full flag)**: Forces complete filter regeneration for all peers, regardless of changes. Useful for:
- Initial deployment
- Recovery after configuration issues  
- Periodic full refresh
- Testing complete filter sets

## Output

The script generates RouterOS v7 commands in the following format:

### IPv4 Example
```
# IPv4 prefix list for Example Peer (AS65001)
/routing filter rule
add chain="IMPORT-65001-IPv4" rule="if (dst in 192.168.0.0/16) {accept}"
add chain="IMPORT-65001-IPv4" rule="if (dst in 10.0.0.0/8) {accept}"
add chain="IMPORT-65001-IPv4" rule="reject"
```

### IPv6 Example
```
# IPv6 prefix list for Example Peer (AS65001)
/routing filter rule
add chain="IMPORT-65001-IPv6" rule="if (dst in 2001:db8::/32) {accept}"
add chain="IMPORT-65001-IPv6" rule="reject"
```

## Filter Names

The script generates filter chains with the following naming convention:
- IPv4: `IMPORT-<ASN>-IPv4`
- IPv6: `IMPORT-<ASN>-IPv6`

Where `<ASN>` is the AS number without the "AS" prefix.

## Output Files

If SSH is disabled or fails, the script saves commands to files in the output directory:
- Format: `prefix-filter-<ASN>.rsc`
- Example: `prefix-filter-65001.rsc`

These files can be imported into RouterOS using:
```
/import file-name=prefix-filter-65001.rsc
```

## Logging

The script generates logs in `bgp_filter_generator.log` with information about:
- IRR queries and responses
- AS-SET expansion results
- Prefix aggregation statistics
- SSH connection attempts
- Error messages and warnings

## Troubleshooting

### Common Issues

1. **IRR Connection Timeout**
   - Check internet connectivity
   - Try a different IRR server
   - Increase timeout values in the code

2. **SSH Connection Failed**
   - Verify router hostname/IP and port
   - Check username/password
   - Ensure SSH is enabled on the router
   - Check firewall rules

3. **No Prefixes Found**
   - Verify AS-SET exists in IRR
   - Check AS-SET spelling and case
   - Some AS-SETs may be empty or outdated

4. **Invalid Prefixes**
   - The script filters out invalid prefixes automatically
   - Check logs for warnings about skipped prefixes

### Dependencies

If you get import errors for `paramiko`, you can still use the script without SSH functionality. The script will save commands to files instead.

## Security Notes

- Store router passwords securely
- Consider using SSH keys instead of passwords
- Limit SSH access to management networks
- Review generated filters before applying them

## License

This project is licensed under the terms of the GNU General Public License v3.0, which ensures that any distributed modifications remain free and open-source.
