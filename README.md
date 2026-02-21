# HoneyPot System

Multi-protocol honeypot for detecting and logging cyber attacks.

## Supported Protocols

- **SSH** (Port 2222) - Captures login attempts
- **FTP** (Port 2121) - Logs commands and credentials
- **HTTP** (Port 8080) - Records web requests
- **Telnet** (Port 2323) - Tracks login attempts

## Installation

```bash
git clone https://github.com/Veicna/honeypot.git
cd honeypot
chmod +x honeypot.py
```

Requirements: Python 3.7+

## Usage

### Start HoneyPot

```bash
python honeypot.py
Note: If you are a Linux user, you should use "python3".
```

### Custom Ports

```bash
python honeypot.py --ssh-port 22222 --ftp-port 21 --http-port 80
```

### Test System

```bash
# Terminal 1
python honeypot.py

# Terminal 2
python test_honeypot.py
```

### Analyze Logs

```bash
python analyze_logs.py
python analyze_logs.py --detailed
python analyze_logs.py --export-csv
```

## Log Files

```
logs/
├── honeypot_main.log          # main system log
├── honeypot_events.json       # structured events
├── ssh_port_2222.log         # SSH attacks
├── ftp_port_2121.log         # FTP attacks
├── http_port_8080.log        # HTTP requests
└── telnet_port_2323.log      # Telnet attempts
```

## Manual Testing

```bash
# SSH
nc localhost 2222

# FTP
nc localhost 2121
USER admin
PASS 123456
QUIT

# HTTP
curl http://localhost:8080

# Telnet
nc localhost 2323
```

## Command Line Options

### honeypot.py

| Option | Default | Description |
|--------|---------|-------------|
| --log-dir | logs | Log directory |
| --ssh-port | 2222 | SSH port |
| --ftp-port | 2121 | FTP port |
| --http-port | 8080 | HTTP port |
| --telnet-port | 2323 | Telnet port |

### analyze_logs.py

| Option | Default | Description |
|--------|---------|-------------|
| --log-dir | logs | Log directory |
| --detailed | - | Show detailed attacks |
| --export-csv | - | Export CSV report |
| --limit | 20 | Max attacks to display |

## Architecture

```
HoneyPot (Main Class)
├── SSH Service (Thread)
├── FTP Service (Thread)
├── HTTP Service (Thread)
└── Telnet Service (Thread)
```

Each service runs independently and handles multiple connections concurrently.

## Example Code

```python
from honeypot import HoneyPot, SSHHoneyPot, FTPHoneyPot

hp = HoneyPot(log_dir="my_logs")
hp.add_service(SSHHoneyPot(port=2222))
hp.add_service(FTPHoneyPot(port=2121))
hp.start()
```

## Security Notes

 **WARNING**: Educational purposes only!

- Use only in isolated test environments
- Never deploy on production networks
- Use proper firewall rules
- Encrypt sensitive log files
- Legal authorization required

## Sample Output

```
╔═══════════════════════════════════════════════════════════╗
║              HoneyPot Security System                     ║
╚═══════════════════════════════════════════════════════════╝

[2025-01-31 14:30:00] [INFO] HoneyPot starting...
[2025-01-31 14:30:00] [INFO] SSH HoneyPot started on port 2222
[2025-01-31 14:30:00] [INFO] FTP HoneyPot started on port 2121
[2025-01-31 14:30:05] [ALERT] ATTACK DETECTED! Service: SSH, IP: 192.168.1.100
```

## Features

- Multi-threaded architecture
- Real-time logging (text + JSON)
- IP address tracking
- Command logging
- CSV export support
- Statistical analysis
- Minimal dependencies

## License

MIT

## Disclaimer

This tool is for educational and research purposes only. Unauthorized use against systems you don't own is illegal. The author is not responsible for misuse.
