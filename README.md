# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/UME01/threat-hunting-scenario-tor-/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “employee” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop. These events began at: 2025-07-28T18:05:36.0526259Z


**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "ume-vm-test"
| where InitiatingProcessAccountName == "chiemelie_cyber_vm"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-07-28T18:05:36.0526259Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="1822" height="357" alt="image" src="https://github.com/user-attachments/assets/d523585f-7ffb-4157-b348-53771a2b16e1" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2024-11-08T22:16:47.4484567Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "ume-vm-test"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.5.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1837" height="306" alt="image" src="https://github.com/user-attachments/assets/b5684b73-509f-45c6-aec6-6591a246ed56" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “chiemelie_cyber_vm” actually opened the tor browser. There was evidence that they did open it at2025-07-28T18:41:06.0013433Z. There were several other instances of firefox.


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "ume-vm-test"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

c
```
<img width="1847" height="255" alt="image" src="https://github.com/user-attachments/assets/e4bd409a-b769-46a0-b71a-020d08679463" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

At 2025-07-28T18:41:30.7914671Z, the device ume-vm-test, logged in as the user chiemelie_cyber_vm, successfully established a network connection to the IP address 172.127.92.239 on port 9001. The connection was made to the URL https://www.lg47xjxaxri.com using the process tor.exe, located in the folder c:\users\chiemelie_cyber_vm\desktop\tor browser\browser\torbrowser\tor\tor.exe.


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "ume-vm-test"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc

```

<img width="1848" height="293" alt="image" src="https://github.com/user-attachments/assets/9978144f-fec6-452c-adc2-b713f984b10d" />


---

## Chronological Event Timeline 

## Timeline of Events – Tor Browser Activity

**2025-07-28T18:05:36Z**  
On device `ume-vm-test`, logged in as `chiemelie_cyber_vm`, a file containing the string **"tor"** was created on the system. This was part of the initial download and extraction process.

Multiple Tor-related files began appearing on the Desktop and related directories, suggesting the user had downloaded and was unpacking Tor browser files.

---

**2025-07-28T18:06:46Z – 18:12:10Z**  
Several additional Tor-related files were created or modified in local application data and temporary Windows directories.

One notable creation was a text file named **`tor-shopping-list.txt`** on the desktop, indicating possible intent for further activity or instructions.

The system showed unpacking actions consistent with installer extraction (e.g., `chrome_Unpacker_BeginUnzip` temp directories being populated with Tor browser resources).

---

**2025-07-28T18:19:15Z**  
The user executed the file **`tor-browser-windows-x86_64-portable-14.5.5.exe`** from the Downloads folder.

The execution command in the logs indicated a **silent installation**, meaning no visible installer prompts would have been shown during setup.

---

**2025-07-28T18:41:06Z**  
Evidence from process creation logs confirmed that **`tor.exe`** was launched by the user account `chiemelie_cyber_vm`.

This indicates the Tor browser application was actually opened, not just installed.

---

**2025-07-28T18:41:30Z**  
While Tor browser was running, the process **`tor.exe`** established a successful outbound network connection to the IP **172.127.92.239** on port **9001**.

The connection was made to the URL:  


---

## Summary – Tor Browser Installation and Usage

On **July 28, 2025**, the user **`chiemelie_cyber_vm`** on the device **`ume-vm-test`** downloaded and installed the Tor browser.

The activity began with the creation of multiple Tor-related files and the appearance of a suspicious text file:  
**`tor-shopping-list.txt`** on the desktop.

Shortly after, the Tor browser installer:  
**`tor-browser-windows-x86_64-portable-14.5.5.exe`**  
was executed via a **silent installation** method.

Within **22 minutes**, the Tor application was launched, and an outbound connection was successfully established to a Tor network node:  
- **IP:** `172.127.92.239`  
- **Port:** `9001`  
- **Domain:** `lg47xjxaxri.com`  

This sequence confirms **successful installation, launch, and network usage** of Tor on the endpoint.


---

## Response Taken

TOR usage was confirmed on the endpoint `ume-vm-test` by the user `chiemelie_cyber_vm`. The device was isolated, and the user's direct manager was notified.

---
