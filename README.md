# Network Recon & Port Scanner

Professional network reconnaissance and port scanning tool with modern web interface.

## Features

- ✅ Network host discovery (ping sweep)
- ✅ Port scanning (Quick/Deep/Service/OS detection)
- ✅ Service version detection
- ✅ OS fingerprinting
- ✅ Real-time scan progress
- ✅ Export reports (PDF/JSON/CSV/XML)
- ✅ Modern dark UI matching professional tools

## Installation

- Requirements: Python 3.8+, Linux recommended (Pop!_OS/Kali/Ubuntu).
- Clone repo and install dependencies (if requirements.txt is included):
    - pip install -r requirements.txt
    - Ensure user has permissions for raw sockets or run with sudo where needed.

## Security and ethics

   - Only scan networks you own or have explicit permission to test.
   - Be mindful that large scans can trigger IDS/IPS or rate limits.
   - Educational project intended for lab use and coursework compliance.

## Troubleshooting

   - Permission errors with ICMP or raw sockets: try sudo python3 main.py ...
   - Module import or main.py errors: verify Python 3 path and dependencies.
   - No live hosts detected: confirm correct subnet and local interface status.

## Screenshots of GUI:

<img width="1170" height="779" alt="Screenshot from 2025-11-02 10-32-12" src="https://github.com/user-attachments/assets/2db58b02-5d02-462e-ad95-115dad1163f9" />
<img width="1106" height="779" alt="Screenshot from 2025-11-02 10-29-53" src="https://github.com/user-attachments/assets/059df0fb-3ea5-43e2-901b-5d87a58369be" />
<img width="1177" height="692" alt="Screenshot from 2025-11-02 10-29-13" src="https://github.com/user-attachments/assets/11ad70b9-d20e-4295-b2dd-adea179da478" />
<img width="1847" height="911" alt="Screenshot from 2025-11-02 10-26-12" src="https://github.com/user-attachments/assets/9cd06bb3-4c3f-430e-a2ec-211c379d2916" />

