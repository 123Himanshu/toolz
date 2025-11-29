#!/usr/bin/env python3
"""Test GMP connection to OpenVAS"""

from gvm.connections import UnixSocketConnection, TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
import socket

# Try different connection methods
methods = [
    ("Unix Socket", lambda: UnixSocketConnection(path='/run/gvmd/gvmd.sock')),
    ("TLS 9390", lambda: TLSConnection(hostname='localhost', port=9390, timeout=10)),
    ("TLS 9392", lambda: TLSConnection(hostname='localhost', port=9392, timeout=10)),
]

for name, conn_func in methods:
    try:
        print(f"\nTrying {name}...")
        conn = conn_func()
        
        with Gmp(connection=conn, transform=EtreeTransform()) as gmp:
            print("  Authenticating...")
            gmp.authenticate('admin', 'admin')
            
            print(f"  ✅ {name} Connection successful!")
            
            version = gmp.get_version()
            print(f"  OpenVAS Version: {version.find('version').text}")
            break
        
    except FileNotFoundError as e:
        print(f"  ❌ Socket not found: {e}")
    except socket.error as e:
        print(f"  ❌ Socket error: {e}")
    except Exception as e:
        print(f"  ❌ Failed: {e}")
else:
    print("\n❌ All connection methods failed")
