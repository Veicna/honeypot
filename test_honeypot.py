#!/usr/bin/env python3
import socket
import time


def test_ssh(port=2222):
    print(f"\n{'='*60}")
    print(f"Testing SSH HoneyPot (Port {port})...")
    print(f"{'='*60}")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('localhost', port))
        
        banner = sock.recv(1024)
        print(f"✓ Connection successful!")
        print(f"  Banner received: {banner.decode('utf-8', errors='ignore').strip()}")
        
        sock.send(b"SSH-2.0-OpenSSH_8.0\r\n")
        response = sock.recv(1024)
        print(f"  Response: {len(response)} bytes")
        
        sock.close()
        print("✓ SSH test passed!")
        return True
        
    except Exception as e:
        print(f"✗ SSH test failed: {e}")
        return False


def test_ftp(port=2121):
    print(f"\n{'='*60}")
    print(f"Testing FTP HoneyPot (Port {port})...")
    print(f"{'='*60}")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('localhost', port))
        
        welcome = sock.recv(1024)
        print(f"✓ Connection successful!")
        print(f"  Welcome: {welcome.decode('utf-8', errors='ignore').strip()}")
        
        sock.send(b"USER admin\r\n")
        response = sock.recv(1024)
        print(f"  USER response: {response.decode('utf-8', errors='ignore').strip()}")
        
        sock.send(b"PASS 123456\r\n")
        response = sock.recv(1024)
        print(f"  PASS response: {response.decode('utf-8', errors='ignore').strip()}")
        
        sock.send(b"QUIT\r\n")
        response = sock.recv(1024)
        print(f"  QUIT response: {response.decode('utf-8', errors='ignore').strip()}")
        
        sock.close()
        print("✓ FTP test passed!")
        return True
        
    except Exception as e:
        print(f"✗ FTP test failed: {e}")
        return False


def test_http(port=8080):
    print(f"\n{'='*60}")
    print(f"Testing HTTP HoneyPot (Port {port})...")
    print(f"{'='*60}")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('localhost', port))
        
        request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        sock.send(request)
        
        response = sock.recv(4096)
        print(f"✓ Connection successful!")
        print(f"  Response: {len(response)} bytes")
        
        first_line = response.decode('utf-8', errors='ignore').split('\n')[0]
        print(f"  Status: {first_line.strip()}")
        
        sock.close()
        print("✓ HTTP test passed!")
        return True
        
    except Exception as e:
        print(f"✗ HTTP test failed: {e}")
        return False


def test_telnet(port=2323):
    print(f"\n{'='*60}")
    print(f"Testing Telnet HoneyPot (Port {port})...")
    print(f"{'='*60}")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('localhost', port))
        
        prompt = sock.recv(1024)
        print(f"✓ Connection successful!")
        print(f"  Prompt: {prompt.decode('utf-8', errors='ignore').strip()}")
        
        sock.send(b"root\n")
        time.sleep(0.5)
        
        pwd_prompt = sock.recv(1024)
        print(f"  Password prompt: {pwd_prompt.decode('utf-8', errors='ignore').strip()}")
        
        sock.send(b"toor123\n")
        time.sleep(0.5)
        
        response = sock.recv(1024)
        print(f"  Response: {response.decode('utf-8', errors='ignore').strip()}")
        
        sock.close()
        print("✓ Telnet test passed!")
        return True
        
    except Exception as e:
        print(f"✗ Telnet test failed: {e}")
        return False


def main():
    print("\n" + "="*60)
    print("HoneyPot Test Tool")
    print("="*60)
    print("\nWARNING: Make sure HoneyPot is running!")
    print("   (In another terminal: python honeypot.py)")
    print("\nStarting tests in 3 seconds...")
    
    for i in range(3, 0, -1):
        print(f"  {i}...", end='\r')
        time.sleep(1)
    
    print("\n")
    
    results = {
        "SSH": test_ssh(),
        "FTP": test_ftp(),
        "HTTP": test_http(),
        "Telnet": test_telnet()
    }
    
    print(f"\n{'='*60}")
    print("TEST RESULTS")
    print(f"{'='*60}")
    
    for service, result in results.items():
        status = "✓ PASSED" if result else "✗ FAILED"
        print(f"  {service:10} : {status}")
    
    success_count = sum(results.values())
    total_count = len(results)
    
    print(f"\nTotal: {success_count}/{total_count} tests passed")
    
    if success_count == total_count:
        print("\nAll tests passed! HoneyPot is working correctly.")
    else:
        print("\nSome tests failed. Check the logs for details.")
    
    print("\nTip: Check 'logs/' directory to view attack logs.")


if __name__ == "__main__":
    main()
