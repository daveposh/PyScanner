# Network Ping Sweeper

A Python GUI application for network scanning that allows you to discover active hosts on your network using ICMP ping. The application supports single IP addresses, IP ranges, and CIDR notation.

## Author

**David Pospishil**
- GitHub: [David Pospishil](https://github.com/daveposh)
- Created: December 2024

## Features

- Scan networks using:
  - Single IP address
  - IP range (e.g., 192.168.1.1-192.168.1.254)
  - CIDR notation (e.g., 192.168.1.0/24)
- Automatic network detection
- Configurable timeout and packet size
- Hostname resolution
- Real-time results display
- Export results to text file
- Clear inactive hosts
- Stop/resume scanning capability

## Requirements

- Python 3.8 or higher
- macOS, Linux, or Windows operating system
- Network access and appropriate permissions for ICMP ping

## Installation

1. Clone the repository or download the source code:
```bash
git clone <repository-url>
cd <repository-directory>
```

2. Create and activate a virtual environment (recommended):

On macOS/Linux:
```bash
python3 -m venv venv
source venv/bin/activate
```

On Windows:
```bash
python -m venv venv
venv\Scripts\activate
```

3. Install the required packages:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the application:
```bash
python PyScanner.py
```

2. The application will automatically detect your network and populate the network dropdown.

3. Configure your scan:
   - Select a network from the dropdown or enter an IP range manually
   - Adjust timeout and packet size if needed
   - Enable/disable hostname resolution

4. Use the control buttons:
   - Click "Start" to begin scanning
   - "Stop" to pause the scan
   - "Clear All" to remove all results
   - "Clear Inactive" to remove inactive hosts
   - "Export Results" to save results to a text file

## Troubleshooting

### Permission Issues
On Unix-like systems (Linux/macOS), you might need elevated privileges to send ICMP packets:
```bash
sudo python PyScanner.py
```

### No Networks Detected
- Ensure you have active network connections
- Check if your network interface is up
- Verify you have appropriate permissions

### Hostname Resolution Not Working
- Check your DNS server configuration
- Ensure you have internet connectivity for external DNS resolution
- Some hosts might not have PTR records set up

## Notes

- Scanning large networks may take some time
- Some networks/hosts might block ICMP packets
- Hostname resolution may slow down the scanning process

## License

This project is licensed under the MIT License - see the LICENSE file for details. 