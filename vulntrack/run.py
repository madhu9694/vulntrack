"""
VulnTrack Application Runner.

Launch the local development web server:
    python run.py
"""

import os
from app import create_app

app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() in ['true', '1', 't']
    print(f"\n==================================================================")
    print(f"[INFO] VulnTrack VAPT Management Platform Starting...")
    print(f"[+] Dashboard URL : http://127.0.0.1:{port}")
    print(f"[+] Default Login : admin / Admin@VulnTrack2026!")
    print(f"[!] Scope Notice  : Use strictly on explicitly authorized targets!")
    print(f"==================================================================\n")
    app.run(host='127.0.0.1', port=port, debug=debug)
