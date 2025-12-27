# Forward_Req Usage Guide

## Project Overview

Forward_Req is a TCP/UDP port forwarding tool built with Python that features a web-based management interface.

## Repository Structure
- **Main File**: `main.py` (located in the project root directory)
- **Configuration**: `forward_config.json` (auto-generated)
- **License**: `LICENSE`
- **Documentation**: `README.md`

## Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/hexo141/Forward_Req/
cd Forward_Req
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

**Required packages** (create `requirements.txt` if not present):
```
fastapi>=0.100.0
uvicorn[standard]>=0.23.0
jinja2>=3.1.0
```

### 3. Basic Usage

#### Start with Web Interface (Recommended)
```bash
python main.py --password YOUR_ADMIN_PASSWORD
```
- Web interface available at: `http://localhost:8080`
- Default web port: 8080 (modify with `--web-port`)

#### Start with Specific Forwarding Rule
```bash
python main.py \
  --password YOUR_ADMIN_PASSWORD \
  --target-host REMOTE_IP \
  --target-port REMOTE_PORT \
  --local-port LOCAL_LISTEN_PORT \
  --protocol tcp \
  --name rule_name
```

#### Run Without Web Interface
```bash
python main.py --password YOUR_ADMIN_PASSWORD --no-web
```

### 4. Web Interface Features
- **Login Page**: Access via browser with admin password
- **Dashboard**: View/control all forwarding rules
- **Management**: Start/stop/delete rules through web UI
- **Statistics**: Monitor connection counts and data transfer
- **Rule Creation**: Add new forwarding rules via web form

### 5. Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--password` | **Required** Admin password | - |
| `--target-host` | Target server IP/hostname | - |
| `--target-port` | Target server port | - |
| `--local-port` | Local listening port | - |
| `--protocol` | Protocol: tcp, udp, or both | tcp |
| `--web-port` | Web management interface port | 8080 |
| `--name` | Forwarding rule name | default |
| `--no-web` | Disable web interface | False |

## Configuration File

The tool automatically creates/uses `forward_config.json` with this structure:
```json
{
  "rule_name": {
    "target_host": "127.0.0.1",
    "target_port": 8080,
    "local_port": 8081,
    "protocol": "tcp"
  }
}
```

## Important Notes

1. **First Run**: Automatically creates default configuration if `forward_config.json` doesn't exist
2. **Authentication**: IP-based with token expiration (1 hour)
3. **Multiple Protocols**: Supports TCP, UDP, or both simultaneously
4. **Background Operation**: Forwarding runs in background threads
5. **Health Check**: Access `http://localhost:8080/health` for service status

## Example Use Cases

### Basic Local Forwarding
```bash
python main.py --password secret123 --target-host 192.168.1.100 --target-port 22 --local-port 2222
```
Forwards local port 2222 to SSH on 192.168.1.100

### UDP Service Forwarding
```bash
python main.py --password secret123 --target-host 10.0.0.5 --target-port 53 --local-port 5353 --protocol udp
```
Forwards DNS queries (UDP port 5353 to 53)

### Web Management Only
```bash
python main.py --password secret123
```
Starts web interface on port 8080 for managing rules through browser

## Troubleshooting

1. **Port Conflicts**: Ensure local ports aren't already in use
2. **Firewall**: Allow traffic on specified local ports
3. **Permissions**: Admin/root may be needed for ports <1024
4. **Web Interface**: Check if `--no-web` flag was accidentally set

This tool provides both command-line and web-based management for flexible TCP/UDP port forwarding operations.
