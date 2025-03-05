<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/ajcyberdefense/threat-hunting-scenario-tor-/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

I first searched the DeviceFileEvent table for any filenames containing the string "tor," which led me to discover that the user biggis1315 had downloaded a Tor installer. This action triggered multiple Tor-related files being copied to the user's desktop, including the creation of a file named "tor-shopping list.txt". These events began on March 5, 2025, at 20:09:12 UTC.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName  == "anthony-windows"
| where InitiatingProcessAccountName == "biggis1315"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-03-05T20:09:12.0310824Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/279efe25-c12a-48c7-b1ba-4cc4e0180c9a)


---

### 2. Searched the `DeviceProcessEvents` Table

Next, I queried the DeviceProcessEvent table specifically looking for process command lines referencing "tor-browser-windows-x86_64-portable-14.0.7.exe". Analysis of these logs indicated that on March 5, 2025, at 3:19 PM, the user biggis1315 executed a portable version of the Tor Browser (version 14.0.7) on a Windows device named "anthony-windows". The executable, located in the user's Downloads folder (**C:\Users\biggis1315\Downloads**), ran with the command "tor-browser-windows-x86_64-portable-14.0.7" without additional parameters. The file’s integrity was verified by a unique SHA-256 hash: a431eeb579236a04283b9f3730aab01ab2ffce21e1411e3959dc650318cf0e13.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "anthony-windows"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.7"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/17d453de-a50a-42df-a639-70d81f45e4c3)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Subsequently, I reviewed the DeviceProcessEvent table again, this time looking specifically for evidence that the employee actively launched the Tor Browser. Evidence confirmed that the browser was opened at 2025-03-05T20:10:03 UTC, with multiple subsequent instances of firefox.exe (Tor) and tor.exe processes spawned thereafter.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "anthony-windows"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe", "start-tor-browser.exe", "torbrowser-install.exe", "browser\firefox.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/06f783d7-45b1-4fa2-afd9-8a4cb0f2d3f6)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Finally, I searched the DeviceNetworkEvent table for any network activity indicative of Tor browser usage, particularly targeting known Tor ports. Logs showed that on March 5, 2025, at 3:20 PM, a process on the device "anthony-windows" successfully established a network connection. This connection, initiated by biggis1315, involved the Tor Browser’s modified Firefox (firefox.exe) located at C:\Users\biggis1315\Desktop\Tor Browser\Browser\firefox.exe, and connected to localhost (127.0.0.1) on port 9150, Tor’s default SOCKS proxy port. This strongly indicated active use of the Tor Browser to anonymize network traffic. 

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "anthony-windows"
| where InitiatingProcessAccountName  == "biggis1315"
| where RemotePort in ("9001", "9030", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileSize, InitiatingProcessFolderPath
| order by Timestamp desc 
```
![image](https://github.com/user-attachments/assets/5f7f81e1-ba7b-4c95-aa60-bc2cf5485c28)


---

## Chronological Event Timeline 

### 1. Tor Browser Installer Downloaded
Timestamp: March 5, 2025, 3:09 PM
Action: File Created
File: "tor-browser-windows-x86_64-portable-14.0.7.exe"
Location: C:\Users\biggis1315\Downloads\
User: "biggis1315"
SHA256: a431eeb579236a04283b9f3730aab01ab2ffce21e1411e3959dc650318cf0e13
📌 User downloaded the Tor Browser installer from an external source and saved it in the Downloads folder.


### 2. Tor Browser Installer Executed
Timestamp: March 5, 2025, 3:19 PM
Action: Process Created
Executable: "tor-browser-windows-x86_64-portable-14.0.7.exe"
Location: C:\Users\biggis1315\Downloads\
Command Line: "tor-browser-windows-x86_64-portable-14.0.7"
User: "biggis1315"
📌 User ran the Tor Browser installer from the Downloads folder.


### 3. Tor Browser Extracted and Files Copied to Desktop
Timestamp: March 5, 2025, 3:29 PM – 3:36 PM
Actions:
Multiple files copied into the Desktop\Tor Browser\ folder.
A text file named "tor-shopping list.txt" was created in Desktop\tor shopping\.
Shortcuts and link files related to Tor Browser were created in system folders.
📌 After running the installer, files were extracted, and a folder structure was created on the Desktop. Additionally, a file named "tor-shopping list.txt" suggests user intent/planning related to Tor.


### 4. Tor Browser Executed
Timestamp: March 5, 2025, 3:10 PM (earliest evidence)
Action: Process Created
Executable: "firefox.exe" (Tor's modified version) & "tor.exe"
Location: C:\Users\biggis1315\Desktop\Tor Browser\Browser\
User: "biggis1315"
📌 User successfully launched the Tor Browser from the desktop folder.


### 5. Network Connection via Tor
Timestamp: March 5, 2025, 3:20 PM
Action: Connection Success
Remote IP: 127.0.0.1
Port: 9150 (Tor SOCKS proxy)
Executable: "firefox.exe" (Tor Browser)"
Location: C:\Users\biggis1315\Desktop\Tor Browser\Browser\
File Size: 1.7 MB
User: "biggis1315"
📌 Tor Browser successfully established a connection using the SOCKS proxy on port 9150, indicating the browser was actively routing traffic through the Tor network.


### 6. External Connection to a Known Tor Relay
Timestamp: March 5, 2025, 3:20 PM
Action: Connection Success
Remote IP: 45.154.28.70
Port: 9001 (Tor Relay Port)
User: "biggis1315"
Remote URL: "https://www.qqzndiird2cqiwxrv.com"
📌 The Tor Browser made an external connection to a known Tor relay, confirming active usage of the Tor network.


---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `anthony-windows` by the user `biggis1315`. The device was isolated, and the user's direct manager was notified.

---
