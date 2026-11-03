# SecureWork AI — Project Context for Codex

## Project Identity
**Title:** SecureWork AI – AI-Powered Secure BYOD Workspace and Intrusion Detection System  
**Type:** Final-year B.Tech CSE (AI&ML) project

**Team 19**
- Sriahari Harkar — 23261A6648
- M. Tharun Reddy — 23261A6626
- A. Prabhas — 23261A6602
- Supervisor: Mrs. Rajini Parimala
- Department: CSE (AI&ML), Department of Emerging Technologies
- Institute: Mahatma Gandhi Institute of Technology (MGIT)

## 1. Problem
Personal laptops used for work can expose organizational data and services to malware, unauthorized applications, network attacks, and data leakage. Enterprise endpoint-security solutions can be expensive or complex for small organizations.

## 2. Core Idea
SecureWork AI is a Windows desktop application that provides a protected work environment on a personal laptop. The user launches one application, authenticates, verifies an approved USB Wi-Fi adapter, enters secure work mode, and receives continuous security monitoring.

Core modules:
1. User authentication
2. Secure Work Mode
3. Approved USB Wi-Fi adapter verification
4. Network traffic monitoring
5. AI/ML intrusion detection
6. Process monitoring
7. Application access control / whitelisting
8. Integrated secure workspace
9. Security alerts and logs
10. Admin dashboard
11. Optional VirtualBox-backed isolation
12. Future controlled support for selected personal applications

## 3. Intended User Flow
User launches SecureWork AI
→ Authentication
→ Verify approved USB Wi-Fi adapter
→ Check network
→ Activate security monitoring
→ Enter Secure Work Mode
→ Use approved work applications
→ Continuously monitor network/system/application activity
→ Generate alerts/logs for suspicious activity
→ Logout/exit work mode

The user should not need to manually start VirtualBox during normal use.

## 4. Secure Workspace
Eventually provide controlled access to:
- Secure Mail
- Spreadsheet
- Document Editor
- Company Browser
- Company Chat
- File Manager
- Calendar/Notes

These can be lightweight integrated tools or controlled application launchers; they do not need to reproduce Microsoft Office.

## 5. USB Wi-Fi Adapter
The system should detect and verify an approved external USB Wi-Fi adapter.

Behavior:
- Adapter detected and approved → allow secure mode
- Missing/unapproved → warn or deny secure mode

Important limitation: the USB adapter alone does NOT guarantee network security or prevent another device from connecting to office Wi-Fi. Network-side authentication/security controls are required. In this project, the adapter is an authorization/control factor.

## 6. AI/ML IDS
Initial model: **Random Forest**

Potential comparison/future models:
- XGBoost
- SVM
- DNN
- LSTM
- Autoencoder

Datasets:
- UNSW-NB15
- CIC-IDS2017

Recommended first pipeline:
Dataset → preprocessing → feature selection → train/test split → Random Forest → evaluation → saved model → live feature extraction → prediction → alert/log.

Metrics:
- Accuracy
- Precision
- Recall
- F1-score
- False Positive Rate
- Detection Time
- CPU usage
- Memory usage

Never fabricate ML results; report only measured experiments.

## 7. Network Monitoring
Use:
- Npcap
- Scapy

Possible features:
- Source/destination IP
- Source/destination port
- Protocol
- Packet size
- TCP flags
- Flow statistics
- Other features compatible with the selected dataset where practical

Start with safe monitoring and analysis. Do not implement offensive network attacks.

## 8. Process Monitoring
Use `psutil` initially.

Monitor:
- Process name
- PID
- CPU usage
- Memory usage
- Executable path
- Network connections where available

Start with detection + alerting before aggressive blocking.

## 9. Application Control
Maintain an approved application policy. Example:
- SecureWork AI
- Company Browser
- Secure Mail
- Secure Docs
- Secure Spreadsheet
- Company Chat
- File Manager

Initial priority:
1. Detect unauthorized application
2. Log it
3. Alert user/admin
4. Add carefully controlled blocking later

Do not implement destructive process-killing behavior without safeguards.

## 10. Secure Work Mode
Use a custom controlled/kiosk-like workspace combined with Windows security controls. Do not claim that standard Windows Kiosk Mode alone solves the whole problem.

Future scope: allow selected personal applications while continuously monitoring and protecting organizational data.

## 11. Admin Dashboard
Eventually include:
- Users
- Devices
- Security alerts
- Activity logs
- Application policies
- Security status
- Remote lock/logout concept
- Policy management

A local dashboard is sufficient for the first prototype.

## 12. VirtualBox / Isolation
Possible architecture:

Windows Host
→ SecureWork AI
→ Security Controller
→ VirtualBox
→ Isolated Secure Workspace

Do not make VirtualBox the first milestone. First make the desktop application, authentication, USB verification, monitoring, and ML IDS work. Integrate VM/isolation later.

## 13. Recommended Technology Stack
| Component | Technology |
|---|---|
| OS | Windows 10/11 64-bit |
| Language | Python 3.11+ |
| GUI | PySide6 |
| ML | scikit-learn |
| Initial model | Random Forest |
| Network capture | Npcap |
| Packet analysis | Scapy |
| Process monitoring | psutil |
| Local DB | SQLite |
| Optional backend | FastAPI |
| Future DB | PostgreSQL |
| VM/isolation | VirtualBox |
| Dataset | UNSW-NB15 |
| Secondary dataset | CIC-IDS2017 |
| IDE | VS Code |
| Version control | Git/GitHub |
| Packaging | PyInstaller |

## 14. Recommended Project Structure
```text
SecureWorkAI/
├── app/
│   ├── main.py
│   ├── ui/
│   │   ├── login.py
│   │   ├── dashboard.py
│   │   └── workspace.py
│   ├── security/
│   │   ├── ids.py
│   │   ├── network_monitor.py
│   │   ├── process_monitor.py
│   │   └── usb_checker.py
│   ├── ml/
│   │   ├── train.py
│   │   ├── predict.py
│   │   └── model.py
│   ├── database/
│   │   ├── database.py
│   │   └── models.py
│   ├── policies/
│   │   └── application_policy.py
│   └── utils/
│       └── logger.py
├── dataset/
├── models/
├── logs/
├── tests/
├── requirements.txt
├── README.md
└── .gitignore
```

Codex may improve this structure when there is a clear engineering reason, but keep modules separated and explain structural changes.

## 15. Development Phases
### Phase 1 — Foundation
- Project structure
- Python environment
- PySide6 application
- Login
- Dashboard
- Logging

### Phase 2 — USB Verification
- Detect USB Wi-Fi adapter
- Identify adapter/interface
- Verify approved device
- Display status

### Phase 3 — Network Monitoring
- Configure Npcap
- Capture traffic safely
- Parse packets
- Extract features

### Phase 4 — ML IDS
- Use UNSW-NB15
- Preprocess
- Train Random Forest
- Evaluate
- Save/load model

### Phase 5 — Real-Time IDS
- Connect live monitoring to trained model
- Predict normal/attack
- Alert and log

### Phase 6 — Process Monitoring
- Monitor Windows processes
- Detect suspicious/unapproved applications
- Log events

### Phase 7 — Application Control
- Approved application list
- Detect unauthorized applications
- Alert
- Carefully implement blocking

### Phase 8 — Secure Workspace
- Work-mode interface
- Approved work tools
- Secure file/application access

### Phase 9 — Admin Dashboard
- Alerts
- Logs
- Users
- Devices
- Policies

### Phase 10 — VirtualBox Integration
- Optional isolated environment
- Backend VM control
- Workspace isolation

### Phase 11 — Testing
- Functional testing
- IDS performance
- False positives
- Resource consumption
- Security testing
- Usability testing

### Phase 12 — Final Packaging
- Windows executable
- Documentation
- Demonstration scenario
- Final report/PPT

## 16. Engineering Rules
1. Do not build the entire project in one step.
2. Keep the application runnable after every major change.
3. Prefer simple, explainable final-year-project implementations.
4. Never fabricate security or ML results.
5. Do not claim enterprise-grade protection.
6. Do not implement offensive cybersecurity functionality.
7. Test security controls in a controlled local environment.
8. Log important security events.
9. Fail safely: if a security check cannot be verified, warn or deny secure mode.
10. Keep secrets/passwords out of source code in the final implementation.
11. Never store passwords in plaintext in the final version.
12. Use Git commits after meaningful milestones.
13. Write tests for important security logic.
14. Document limitations honestly.
15. Do not add unnecessary technologies without a project need.

## 17. First Milestone — Foundation Only
Implement only:
- Working Python project
- PySide6 GUI
- Login screen
- Demo authentication
- Dashboard
- Basic status cards
- Logging
- README
- requirements.txt
- Git-friendly structure

Do NOT implement yet:
- Live packet capture
- Real IDS
- Application blocking
- Malware execution
- Ransomware simulation
- Offensive network attacks
- VirtualBox automation

After the foundation works, proceed to USB Wi-Fi adapter verification.

## 18. Codex Instructions
Before modifying the project:
1. Read this file.
2. Inspect the existing repository.
3. Understand existing code before replacing it.
4. Make small, testable changes.
5. Run relevant tests or launch checks.
6. Report exactly what changed.
7. Report commands used for testing.
8. Report errors honestly.
9. Do not silently delete working functionality.
10. Ask before making large architectural changes.

The goal is a working, demonstrable academic prototype, not an unnecessarily complicated enterprise platform.
