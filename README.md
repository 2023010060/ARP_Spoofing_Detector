# ARP Shield — ARP Spoofing Detection & Network Monitoring System

A beginner-friendly but professional final-year cybersecurity project for detecting suspicious ARP/IP-to-MAC changes and monitoring the local ARP table.

## Features

1. Professional desktop GUI
2. Local IPv4 and default-gateway discovery
3. Manual ARP scan
4. Continuous/automatic scanning
5. ARP table monitoring
6. Baseline IP-to-MAC learning
7. Detection of MAC changes for the same IP
8. Special alert when the default gateway MAC changes
9. Security-alert history
10. CSV export
11. PDF security report generation
12. Activity log
13. Configurable scan interval
14. Safe network metadata monitoring

## Important safety boundary

The reference screenshot mentions "capture passwords". This implementation intentionally does **not** capture passwords, credentials, authentication tokens, or packet payloads. Credential interception is unsafe and is not needed to demonstrate ARP spoofing detection.

Instead, the project demonstrates the defensive part: identifying suspicious ARP mapping changes and documenting the evidence.

## Windows setup

### 1. Install Python

Use Python 3.11 or newer.

Check:

```text
python --version
```

### 2. Open this folder in VS Code

Open the project folder:

```text
ARP_Spoofing_Detector
```

### 3. Create a virtual environment

```text
python -m venv .venv
```

Activate it in PowerShell:

```text
.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, run the commands below directly with the Python executable:

```text
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 4. Install dependencies

```text
python -m pip install -r requirements.txt
```

### 5. Run

```text
python main.py
```

## What you should see

The GUI contains:

- Local IPv4
- Default gateway
- Scan count
- Start Monitoring
- Stop
- Scan Now
- Export CSV
- Generate PDF Report
- ARP Table tab
- Security Alerts tab
- Activity Log tab

## Demonstration workflow

1. Start the program.
2. Click **Scan Now**.
3. The first scan creates a baseline.
4. Click **Start Monitoring**.
5. Leave the program running for several scans.
6. The ARP table is refreshed automatically.
7. If an IP-to-MAC mapping changes, the tool creates a security alert.
8. Use **Generate PDF Report** for the project demonstration.

## How ARP spoofing detection works

Normally a device has a mapping similar to:

```text
192.168.1.1  ->  aa:bb:cc:dd:ee:ff
```

The application remembers this mapping.

If a later scan reports:

```text
192.168.1.1  ->  11:22:33:44:55:66
```

the same IP now points to a different MAC address. That is a strong indicator that something changed and may indicate ARP spoofing.

The program does not automatically claim every change is an attack. The report calls it a "possible anomaly" so that the user can investigate.

## Project architecture

```text
                 +----------------------+
                 |     ARP Shield GUI   |
                 |      Tkinter         |
                 +----------+-----------+
                            |
             +--------------+--------------+
             |                             |
       +-----v------+                +-----v------+
       | ARP Table  |                | System Info|
       | arp -a     |                | ipconfig   |
       +-----+------+                +-----+------+
             |                             |
             +--------------+--------------+
                            |
                     +------v------+
                     | Detection   |
                     | Engine      |
                     +------+------+
                            |
              +-------------+-------------+
              |                           |
       +------v------+              +-----v------+
       | Alert Log   |              | Reporting  |
       | GUI + CSV   |              | PDF        |
       +-------------+              +------------+
```

## Files

- `main.py` — complete application
- `requirements.txt` — Python dependencies
- `README.md` — setup and explanation

## Optional future enhancement

For a research/demo version, a Scapy-based ARP packet observer can be added to record ARP packet metadata. It should remain limited to defensive metadata and should not collect credentials or packet payloads.
