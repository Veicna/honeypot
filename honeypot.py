#!/usr/bin/env python3
import socket
import threading
import datetime
import json
from pathlib import Path
import argparse


class HoneyPot:
    
    def __init__(self, log_dir="logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.running = True
        self.services = []
        
        self.main_log = self.log_dir / "honeypot_main.log"
        self.json_log = self.log_dir / "honeypot_events.json"
        
        self._log_event("HoneyPot starting...", level="INFO")
    
    def _log_event(self, message, level="INFO", data=None):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] [{level}] {message}\n"
        
        print(log_message.strip())
        
        with open(self.main_log, "a", encoding="utf-8") as f:
            f.write(log_message)
        
        if data:
            json_entry = {
                "timestamp": timestamp,
                "level": level,
                "message": message,
                "data": data
            }
            with open(self.json_log, "a", encoding="utf-8") as f:
                f.write(json.dumps(json_entry, ensure_ascii=False) + "\n")
    
    def add_service(self, service):
        self.services.append(service)
        service.honeypot = self
    
    def start(self):
        threads = []
        for service in self.services:
            thread = threading.Thread(target=service.start, daemon=True)
            thread.start()
            threads.append(thread)
            self._log_event(f"{service.name} started on port {service.port}", level="INFO")
        
        self._log_event("All services active! Press CTRL+C to stop.", level="SUCCESS")
        
        try:
            while self.running:
                threading.Event().wait(1)
        except KeyboardInterrupt:
            self._log_event("Shutting down...", level="WARNING")
            self.running = False
    
    def log_attack(self, service_name, attacker_ip, port, data):
        attack_data = {
            "service": service_name,
            "attacker_ip": attacker_ip,
            "port": port,
            "data": data
        }
        
        self._log_event(
            f"ATTACK DETECTED! Service: {service_name}, IP: {attacker_ip}, Port: {port}",
            level="ALERT",
            data=attack_data
        )


class SSHHoneyPot:
    
    def __init__(self, port=2222):
        self.name = "SSH HoneyPot"
        self.port = port
        self.honeypot = None
        self.log_file = None
        
    def start(self):
        if self.honeypot:
            self.log_file = self.honeypot.log_dir / f"ssh_port_{self.port}.log"
        
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind(('0.0.0.0', self.port))
            server.listen(5)
            
            while self.honeypot.running:
                try:
                    client, address = server.accept()
                    threading.Thread(
                        target=self._handle_client,
                        args=(client, address),
                        daemon=True
                    ).start()
                except:
                    break
        except Exception as e:
            if self.honeypot:
                self.honeypot._log_event(f"SSH error: {e}", level="ERROR")
        finally:
            server.close()
    
    def _handle_client(self, client, address):
        ip = address[0]
        
        try:
            banner = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
            client.send(banner)
            
            data = client.recv(4096)
            
            if data:
                decoded_data = data.decode('utf-8', errors='ignore')
                
                log_entry = f"""
{'='*80}
Timestamp: {datetime.datetime.now()}
IP Address: {ip}
Port: {self.port}
Protocol: SSH
Data Length: {len(data)} bytes
Data (Raw): {data.hex()}
Data (Decoded): {decoded_data}
{'='*80}
"""
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(log_entry)
                
                self.honeypot.log_attack(
                    service_name="SSH",
                    attacker_ip=ip,
                    port=self.port,
                    data=decoded_data[:200]
                )
                
                client.send(b"\x00\x00\x00\x0c\x05\x14\x00\x00\x00\x00\x00\x00\x00\x00")
            
        except:
            pass
        finally:
            client.close()


class FTPHoneyPot:
    
    def __init__(self, port=2121):
        self.name = "FTP HoneyPot"
        self.port = port
        self.honeypot = None
        self.log_file = None
        
    def start(self):
        if self.honeypot:
            self.log_file = self.honeypot.log_dir / f"ftp_port_{self.port}.log"
        
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind(('0.0.0.0', self.port))
            server.listen(5)
            
            while self.honeypot.running:
                try:
                    client, address = server.accept()
                    threading.Thread(
                        target=self._handle_client,
                        args=(client, address),
                        daemon=True
                    ).start()
                except:
                    break
        except Exception as e:
            if self.honeypot:
                self.honeypot._log_event(f"FTP error: {e}", level="ERROR")
        finally:
            server.close()
    
    def _handle_client(self, client, address):
        ip = address[0]
        commands = []
        
        try:
            client.send(b"220 Welcome to FTP Server\r\n")
            
            while True:
                data = client.recv(1024)
                if not data:
                    break
                
                command = data.decode('utf-8', errors='ignore').strip()
                commands.append(command)
                
                if command.upper().startswith('USER'):
                    client.send(b"331 Password required\r\n")
                elif command.upper().startswith('PASS'):
                    client.send(b"530 Login incorrect\r\n")
                elif command.upper().startswith('QUIT'):
                    client.send(b"221 Goodbye\r\n")
                    break
                else:
                    client.send(b"502 Command not implemented\r\n")
            
            log_entry = f"""
{'='*80}
Timestamp: {datetime.datetime.now()}
IP Address: {ip}
Port: {self.port}
Protocol: FTP
Commands Executed:
{chr(10).join(f'  - {cmd}' for cmd in commands)}
{'='*80}
"""
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(log_entry)
            
            self.honeypot.log_attack(
                service_name="FTP",
                attacker_ip=ip,
                port=self.port,
                data=", ".join(commands)
            )
            
        except:
            pass
        finally:
            client.close()


class HTTPHoneyPot:
    
    def __init__(self, port=8080):
        self.name = "HTTP HoneyPot"
        self.port = port
        self.honeypot = None
        self.log_file = None
        
    def start(self):
        if self.honeypot:
            self.log_file = self.honeypot.log_dir / f"http_port_{self.port}.log"
        
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind(('0.0.0.0', self.port))
            server.listen(5)
            
            while self.honeypot.running:
                try:
                    client, address = server.accept()
                    threading.Thread(
                        target=self._handle_client,
                        args=(client, address),
                        daemon=True
                    ).start()
                except:
                    break
        except Exception as e:
            if self.honeypot:
                self.honeypot._log_event(f"HTTP error: {e}", level="ERROR")
        finally:
            server.close()
    
    def _handle_client(self, client, address):
        ip = address[0]
        
        try:
            data = client.recv(4096)
            
            if data:
                request = data.decode('utf-8', errors='ignore')
                
                response = """HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html
Content-Length: 196

<html>
<head><title>Welcome</title></head>
<body>
<h1>Apache2 Ubuntu Default Page</h1>
<p>It works! This is the default web page for this server.</p>
</body>
</html>"""
                client.send(response.encode())
                
                log_entry = f"""
{'='*80}
Timestamp: {datetime.datetime.now()}
IP Address: {ip}
Port: {self.port}
Protocol: HTTP
Request:
{request}
{'='*80}
"""
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(log_entry)
                
                self.honeypot.log_attack(
                    service_name="HTTP",
                    attacker_ip=ip,
                    port=self.port,
                    data=request.split('\n')[0] if request else "No data"
                )
                
        except:
            pass
        finally:
            client.close()


class TelnetHoneyPot:
    
    def __init__(self, port=2323):
        self.name = "Telnet HoneyPot"
        self.port = port
        self.honeypot = None
        self.log_file = None
        
    def start(self):
        if self.honeypot:
            self.log_file = self.honeypot.log_dir / f"telnet_port_{self.port}.log"
        
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind(('0.0.0.0', self.port))
            server.listen(5)
            
            while self.honeypot.running:
                try:
                    client, address = server.accept()
                    threading.Thread(
                        target=self._handle_client,
                        args=(client, address),
                        daemon=True
                    ).start()
                except:
                    break
        except Exception as e:
            if self.honeypot:
                self.honeypot._log_event(f"Telnet error: {e}", level="ERROR")
        finally:
            server.close()
    
    def _handle_client(self, client, address):
        ip = address[0]
        credentials = []
        
        try:
            client.send(b"\r\nUbuntu 20.04.3 LTS\r\n\r\nlogin: ")
            
            username = client.recv(1024).decode('utf-8', errors='ignore').strip()
            credentials.append(f"Username: {username}")
            
            client.send(b"Password: ")
            password = client.recv(1024).decode('utf-8', errors='ignore').strip()
            credentials.append(f"Password: {password}")
            
            client.send(b"\r\nLogin incorrect\r\n")
            
            log_entry = f"""
{'='*80}
Timestamp: {datetime.datetime.now()}
IP Address: {ip}
Port: {self.port}
Protocol: Telnet
Credentials Attempted:
{chr(10).join(f'  - {cred}' for cred in credentials)}
{'='*80}
"""
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(log_entry)
            
            self.honeypot.log_attack(
                service_name="Telnet",
                attacker_ip=ip,
                port=self.port,
                data=", ".join(credentials)
            )
            
        except:
            pass
        finally:
            client.close()


def print_banner():
    banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║              HoneyPot Security System                     ║
║                                                           ║
║        Multi-protocol deception & monitoring tool         ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

Supported Protocols:
  • SSH   (Port 2222)
  • FTP   (Port 2121)
  • HTTP  (Port 8080)
  • Telnet (Port 2323)

WARNING: Educational purposes only!
Do not use on production systems without authorization.

"""
    print(banner)


def main():
    parser = argparse.ArgumentParser(description='HoneyPot - Attack detection system')
    parser.add_argument('--log-dir', default='logs', help='Log directory')
    parser.add_argument('--ssh-port', type=int, default=2222, help='SSH port')
    parser.add_argument('--ftp-port', type=int, default=2121, help='FTP port')
    parser.add_argument('--http-port', type=int, default=8080, help='HTTP port')
    parser.add_argument('--telnet-port', type=int, default=2323, help='Telnet port')
    
    args = parser.parse_args()
    
    print_banner()
    
    honeypot = HoneyPot(log_dir=args.log_dir)
    
    honeypot.add_service(SSHHoneyPot(port=args.ssh_port))
    honeypot.add_service(FTPHoneyPot(port=args.ftp_port))
    honeypot.add_service(HTTPHoneyPot(port=args.http_port))
    honeypot.add_service(TelnetHoneyPot(port=args.telnet_port))
    
    honeypot.start()


if __name__ == "__main__":
    main()
