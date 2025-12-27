import argparse
import asyncio
import json
import logging
from typing import Optional, Dict, Set
from datetime import datetime, timedelta
import hashlib
import base64
import os
from collections import defaultdict

# Web Framework
from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

# Asynchronous TCP/UDP
import socket
import threading
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SimplePortForwarder:
    """Simple Port Forwarder"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.target_host = config['target_host']
        self.target_port = config['target_port']
        self.local_port = config['local_port']
        self.protocol = config['protocol'].lower()
        self.running = False
        self.stats = {
            'connections': 0,
            'packets': 0,
            'bytes_up': 0,
            'bytes_down': 0,
            'start_time': None,
            'active': 0
        }
        
    def start(self):
        """Start the forwarding service"""
        self.running = True
        self.stats['start_time'] = datetime.now()
        
        if self.protocol in ['tcp', 'both']:
            threading.Thread(target=self._start_tcp, daemon=True).start()
        if self.protocol in ['udp', 'both']:
            threading.Thread(target=self._start_udp, daemon=True).start()
            
        logger.info(f"Forwarding started: local:{self.local_port} -> {self.target_host}:{self.target_port}")
    
    def _start_tcp(self):
        """TCP Forwarding"""
        def tcp_handler(client_socket: socket.socket, addr: tuple):
            try:
                target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                target_socket.connect((self.target_host, self.target_port))
                
                self.stats['active'] += 1
                self.stats['connections'] += 1
                
                # Bidirectional forwarding
                def forward(src, dst, direction):
                    try:
                        while self.running:
                            data = src.recv(8192)
                            if not data:
                                break
                            dst.sendall(data)
                            if direction == 'up':
                                self.stats['bytes_up'] += len(data)
                            else:
                                self.stats['bytes_down'] += len(data)
                    except:
                        pass
                
                threading.Thread(target=forward, args=(client_socket, target_socket, 'up'), daemon=True).start()
                threading.Thread(target=forward, args=(target_socket, client_socket, 'down'), daemon=True).start()
                
                # Keep connection alive until termination
                while self.running and client_socket.fileno() != -1 and target_socket.fileno() != -1:
                    time.sleep(0.1)
                    
            except Exception as e:
                logger.debug(f"TCP error: {e}")
            finally:
                self.stats['active'] = max(0, self.stats['active'] - 1)
                try:
                    client_socket.close()
                except: pass
                try:
                    target_socket.close()
                except: pass
        
        # TCP Server
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', self.local_port))
        server.listen(50)
        
        while self.running:
            try:
                client, addr = server.accept()
                threading.Thread(target=tcp_handler, args=(client, addr), daemon=True).start()
            except:
                if self.running:
                    break
        
        server.close()
    
    def _start_udp(self):
        """UDP Forwarding"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', self.local_port))
        
        while self.running:
            try:
                data, addr = sock.recvfrom(65535)
                self.stats['packets'] += 1
                self.stats['bytes_up'] += len(data)
                
                # Forward to target
                target_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                target_sock.sendto(data, (self.target_host, self.target_port))
                target_sock.settimeout(2)
                
                try:
                    resp, _ = target_sock.recvfrom(65535)
                    sock.sendto(resp, addr)
                    self.stats['bytes_down'] += len(resp)
                except socket.timeout:
                    pass
                finally:
                    target_sock.close()
                    
            except Exception as e:
                if self.running:
                    logger.debug(f"UDP error: {e}")
        
        sock.close()
    
    def stop(self):
        """Stop service"""
        self.running = False
    
    def get_stats(self):
        """Get statistics"""
        stats = self.stats.copy()
        if stats['start_time']:
            uptime = datetime.now() - stats['start_time']
            stats['uptime'] = str(uptime).split('.')[0]
        return stats

class IPAuthManager:
    """IP Authentication Manager"""
    
    def __init__(self, password: str):
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()
        # IP -> (token, expiration time)
        self.authorized_ips: Dict[str, tuple] = {}
        self.cleanup_interval = 300  # Cleanup every 5 minutes
        self.last_cleanup = time.time()
        
    def verify_password(self, password: str) -> bool:
        """Verify password"""
        return hashlib.sha256(password.encode()).hexdigest() == self.password_hash
    
    def authorize_ip(self, ip: str) -> str:
        """Authorize an IP address, return token"""
        # Cleanup expired tokens
        self._cleanup()
        
        # Generate token
        token = base64.b64encode(os.urandom(32)).decode()
        expires = datetime.now() + timedelta(hours=1)
        self.authorized_ips[ip] = (token, expires)
        return token
    
    def verify_ip(self, ip: str, token: str = None) -> bool:
        """Verify IP and token"""
        self._cleanup()
        
        if ip not in self.authorized_ips:
            return False
            
        stored_token, expires = self.authorized_ips[ip]
        
        # Check expiration
        if datetime.now() > expires:
            del self.authorized_ips[ip]
            return False
            
        # If token provided, verify token
        if token and stored_token != token:
            return False
            
        return True
    
    def _cleanup(self):
        """Cleanup expired authorizations"""
        now = time.time()
        if now - self.last_cleanup < self.cleanup_interval:
            return
            
        current_time = datetime.now()
        expired_ips = [
            ip for ip, (_, expires) in self.authorized_ips.items()
            if current_time > expires
        ]
        
        for ip in expired_ips:
            del self.authorized_ips[ip]
            
        self.last_cleanup = now

class ForwardManager:
    """Forwarding Manager"""
    
    def __init__(self, config_file: str = 'forward_config.json'):
        self.config_file = config_file
        self.forwarders: Dict[str, SimplePortForwarder] = {}
        self.auth_manager: Optional[IPAuthManager] = None
        self.load_config()
        
    def set_password(self, password: str):
        """Set password"""
        self.auth_manager = IPAuthManager(password)
        
    def load_config(self):
        """Load configuration"""
        try:
            with open(self.config_file, 'r') as f:
                configs = json.load(f)
                for name, config in configs.items():
                    self.forwarders[name] = SimplePortForwarder(config)
        except FileNotFoundError:
            self.save_config()
    
    def save_config(self):
        """Save configuration"""
        configs = {name: f.config for name, f in self.forwarders.items()}
        with open(self.config_file, 'w') as f:
            json.dump(configs, f, indent=2)
    
    def add_forwarder(self, name: str, config: Dict):
        """Add forwarder"""
        self.forwarders[name] = SimplePortForwarder(config)
        self.save_config()
    
    def start_forwarder(self, name: str):
        """Start forwarder"""
        if name in self.forwarders:
            threading.Thread(target=self.forwarders[name].start, daemon=True).start()
            return True
        return False
    
    def stop_forwarder(self, name: str):
        """Stop forwarder"""
        if name in self.forwarders:
            self.forwarders[name].stop()
            return True
        return False
    
    def remove_forwarder(self, name: str):
        """Remove forwarder"""
        if name in self.forwarders:
            self.forwarders[name].stop()
            del self.forwarders[name]
            self.save_config()
            return True
        return False
    
    def get_stats(self):
        """Get all statistics"""
        return {name: f.get_stats() for name, f in self.forwarders.items()}

# Create FastAPI app
app = FastAPI(title="Simple Port Forwarder")
manager: Optional[ForwardManager] = None

def get_client_ip(request: Request) -> str:
    """Get client IP"""
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.client.host if request.client else '0.0.0.0'

def require_auth(request: Request):
    """Authentication dependency"""
    if not manager or not manager.auth_manager:
        return True
        
    ip = get_client_ip(request)
    token = request.cookies.get("auth_token", "")
    
    if not manager.auth_manager.verify_ip(ip, token):
        raise HTTPException(status_code=403, detail="Please login first")
    
    return True

# Minimal HTML templates
LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body { font-family: monospace; margin: 40px; }
        .box { width: 300px; margin: 0 auto; }
        input, button { 
            display: block; 
            width: 100%; 
            margin: 10px 0; 
            padding: 8px;
            border: 1px solid #ccc;
        }
        button { background: #000; color: #fff; border: none; }
    </style>
</head>
<body>
    <div class="box">
        <h3>Port Forwarding Login</h3>
        <form method="post" action="/login">
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Forwarding Control</title>
    <style>
        body { font-family: monospace; margin: 20px; }
        .header { margin-bottom: 20px; }
        .row { margin: 10px 0; padding: 10px; border: 1px solid #eee; }
        .stat { display: inline-block; margin-right: 20px; }
        .btn { 
            display: inline-block; 
            margin: 2px; 
            padding: 4px 8px; 
            border: 1px solid #000; 
            text-decoration: none; 
            color: #000;
        }
        .btn.start { background: #cfc; }
        .btn.stop { background: #fcc; }
        .btn.del { background: #ccc; }
        form { display: inline; }
        .add-form { margin-top: 30px; padding-top: 20px; border-top: 2px solid #000; }
        .add-form input { margin: 5px; padding: 5px; }
        .logout { float: right; }
    </style>
</head>
<body>
    <div class="header">
        <h2>Port Forwarding Management</h2>
        <a href="/logout" class="btn logout">Logout</a>
    </div>
    
    <h3>Current Forwardings</h3>
    {% for name, f in forwarders %}
    <div class="row">
        <strong>{{ name }}</strong><br>
        <span class="stat">Local:{{ f.config.local_port }}</span>
        <span class="stat">→ {{ f.config.target_host }}:{{ f.config.target_port }}</span>
        <span class="stat">Protocol:{{ f.config.protocol }}</span>
        <span class="stat">Status: {% if f.running %}Running{% else %}Stopped{% endif %}</span>
        
        <div style="margin-top: 5px;">
            {% if f.running %}
            <form method="post" action="/stop/{{ name }}">
                <button class="btn stop" type="submit">Stop</button>
            </form>
            {% else %}
            <form method="post" action="/start/{{ name }}">
                <button class="btn start" type="submit">Start</button>
            </form>
            {% endif %}
            <form method="post" action="/remove/{{ name }}" onsubmit="return confirm('Are you sure?');">
                <button class="btn del" type="submit">Delete</button>
            </form>
        </div>
    </div>
    {% else %}
    <p>No forwarding rules</p>
    {% endfor %}
    
    <div class="add-form">
        <h3>Add Forwarding</h3>
        <form method="post" action="/add">
            <input type="text" name="name" placeholder="Name" required>
            <input type="text" name="target_host" placeholder="Target IP" required>
            <input type="number" name="target_port" placeholder="Target Port" required>
            <input type="number" name="local_port" placeholder="Local Port" required>
            <select name="protocol">
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="both">TCP+UDP</option>
            </select>
            <button class="btn start" type="submit">Add</button>
        </form>
    </div>
    
    <div style="margin-top: 30px; font-size: 12px; color: #666;">
        Your IP: {{ client_ip }}
    </div>
</body>
</html>
"""

STATS_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Statistics</title>
    <style>
        body { font-family: monospace; margin: 20px; }
        .stat { margin: 5px 0; }
        .back { margin-top: 20px; }
        a { color: #000; text-decoration: none; border: 1px solid; padding: 3px 8px; }
    </style>
</head>
<body>
    <h3>Forwarding Statistics</h3>
    {% for name, stats in all_stats %}
    <div style="margin: 15px 0; padding: 10px; border: 1px solid #ddd;">
        <strong>{{ name }}</strong>
        <div class="stat">Connections: {{ stats.connections }}</div>
        <div class="stat">Active: {{ stats.active }}</div>
        <div class="stat">Upload: {{ stats.bytes_up|filesizeformat }}</div>
        <div class="stat">Download: {{ stats.bytes_down|filesizeformat }}</div>
        <div class="stat">Uptime: {{ stats.uptime }}</div>
    </div>
    {% endfor %}
    <div class="back">
        <a href="/dashboard">Back to Dashboard</a>
    </div>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def index():
    """Homepage/Login page"""
    return HTMLResponse(LOGIN_HTML)

@app.post("/login")
async def login(request: Request, password: str = Form(...)):
    """Login verification"""
    if not manager or not manager.auth_manager:
        raise HTTPException(status_code=500, detail="System not initialized")
    
    if manager.auth_manager.verify_password(password):
        ip = get_client_ip(request)
        token = manager.auth_manager.authorize_ip(ip)
        
        response = RedirectResponse(url="/dashboard", status_code=302)
        response.set_cookie(key="auth_token", value=token, httponly=True)
        logger.info(f"IP {ip} logged in successfully")
        return response
    else:
        raise HTTPException(status_code=401, detail="Incorrect password")

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Control Panel"""
    if not manager or not manager.auth_manager:
        return HTMLResponse("System not initialized")
    
    ip = get_client_ip(request)
    token = request.cookies.get("auth_token", "")
    
    if not manager.auth_manager.verify_ip(ip, token):
        return RedirectResponse(url="/", status_code=302)
    
    # Render dashboard
    from jinja2 import Template
    template = Template(DASHBOARD_HTML)
    
    html = template.render(
        forwarders=manager.forwarders.items(),
        client_ip=ip
    )
    return HTMLResponse(html)

@app.get("/stats", response_class=HTMLResponse)
async def stats(request: Request):
    """Statistics page"""
    if not manager or not manager.auth_manager:
        return HTMLResponse("System not initialized")
    
    ip = get_client_ip(request)
    token = request.cookies.get("auth_token", "")
    
    if not manager.auth_manager.verify_ip(ip, token):
        return RedirectResponse(url="/", status_code=302)
    
    stats_data = manager.get_stats()
    from jinja2 import Template
    template = Template(STATS_HTML)
    
    html = template.render(
        all_stats=stats_data.items()
    )
    return HTMLResponse(html)

@app.post("/add")
async def add_forwarder(
    request: Request,
    name: str = Form(...),
    target_host: str = Form(...),
    target_port: int = Form(...),
    local_port: int = Form(...),
    protocol: str = Form(...)
):
    """Add forwarder"""
    ip = get_client_ip(request)
    token = request.cookies.get("auth_token", "")
    
    if not manager or not manager.auth_manager:
        raise HTTPException(status_code=500, detail="System not initialized")
    if not manager.auth_manager.verify_ip(ip, token):
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    config = {
        'target_host': target_host,
        'target_port': target_port,
        'local_port': local_port,
        'protocol': protocol
    }
    
    manager.add_forwarder(name, config)
    return RedirectResponse(url="/dashboard", status_code=302)

@app.post("/start/{name}")
async def start_forwarder(name: str, request: Request):
    """Start forwarder"""
    ip = get_client_ip(request)
    token = request.cookies.get("auth_token", "")
    
    if not manager or not manager.auth_manager:
        raise HTTPException(status_code=500, detail="System not initialized")
    if not manager.auth_manager.verify_ip(ip, token):
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    manager.start_forwarder(name)
    return RedirectResponse(url="/dashboard", status_code=302)

@app.post("/stop/{name}")
async def stop_forwarder(name: str, request: Request):
    """Stop forwarder"""
    ip = get_client_ip(request)
    token = request.cookies.get("auth_token", "")
    
    if not manager or not manager.auth_manager:
        raise HTTPException(status_code=500, detail="System not initialized")
    if not manager.auth_manager.verify_ip(ip, token):
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    manager.stop_forwarder(name)
    return RedirectResponse(url="/dashboard", status_code=302)

@app.post("/remove/{name}")
async def remove_forwarder(name: str, request: Request):
    """Remove forwarder"""
    ip = get_client_ip(request)
    token = request.cookies.get("auth_token", "")
    
    if not manager or not manager.auth_manager:
        raise HTTPException(status_code=500, detail="System not initialized")
    if not manager.auth_manager.verify_ip(ip, token):
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    manager.remove_forwarder(name)
    return RedirectResponse(url="/dashboard", status_code=302)

@app.get("/logout")
async def logout(request: Request):
    """Logout"""
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie("auth_token")
    return response

@app.get("/health")
async def health():
    """Health check"""
    return {"status": "ok", "time": datetime.now().isoformat()}

def create_default_config():
    """Create default config file"""
    default_config = {
        "default": {
            "target_host": "127.0.0.1",
            "target_port": 8080,
            "local_port": 8081,
            "protocol": "tcp"
        }
    }
    with open('forward_config.json', 'w') as f:
        json.dump(default_config, f, indent=2)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Simple Port Forwarding Tool")
    parser.add_argument("--target-host", help="Target host address")
    parser.add_argument("--target-port", type=int, help="Target port")
    parser.add_argument("--local-port", type=int, help="Local listening port")
    parser.add_argument("--protocol", choices=['tcp', 'udp', 'both'], default='tcp', 
                       help="Forwarding protocol")
    parser.add_argument("--web-port", type=int, default=8080, help="Web management port")
    parser.add_argument("--password", required=True, help="Admin password")
    parser.add_argument("--name", default="default", help="Forwarding rule name")
    parser.add_argument("--no-web", action="store_true", help="Do not start web interface")
    
    args = parser.parse_args()
    
    # Create config file
    if not os.path.exists('forward_config.json'):
        create_default_config()
    
    # Initialize manager
    global manager
    manager = ForwardManager()
    manager.set_password(args.password)
    
    # If command line arguments provided, add forwarder
    if args.target_host and args.target_port and args.local_port:
        config = {
            'target_host': args.target_host,
            'target_port': args.target_port,
            'local_port': args.local_port,
            'protocol': args.protocol
        }
        manager.add_forwarder(args.name, config)
        manager.start_forwarder(args.name)
    
    logger.info(f"Password: {args.password}")
    logger.info(f"Web Management: http://localhost:{args.web_port}")
    
    if not args.no_web:
        uvicorn.run(app, host="0.0.0.0", port=args.web_port)
    else:
        # Run forwarding only, no web interface
        logger.info("Web interface disabled, running forwarding service only")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Interrupt received, stopping all forwardings")
            for name in list(manager.forwarders.keys()):
                manager.stop_forwarder(name)

if __name__ == "__main__":
    main()