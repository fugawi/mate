# MATE
MITRE ATT&amp;CK&reg; Technique Emulation - Version: 1.0  
Developed By @Fugawi72 

MATE will iterate over modified Atomic Red Team yaml files and create objects for each test. 
The objects will allow for automating execution of MITRE ATT&CK&reg; techniques to test defenses.

License: https://opensource.org/licenses/BSD-3-Clause

Required Dependencies: powershell-yaml, Install-Module powershell-yaml https://github.com/cloudbase/powershell-yaml

Optional Dependencies: Atomic Red Team yaml files https://github.com/redcanaryco/atomic-red-team/tree/master/atomics
**Atomic files have been modified (CMD, PowerShell, Nix, Manual). Currently automated test limited to Windows only.**

Menu driven PowerShell application  
TestDir - Local directory containing tests (starting directory will be recursed)  **Only .yml or .yaml files will be loaded**  
OutDir - Local output directory for capturing test evidence (command ran along with PID)  
*File will be created for each different command (Ex. sc.exe --> sc.txt)

Thanks to Casey Smith (@subTee) for his initial work on 'Invoke-Atomic' which led to the creation of MATE. A shoutout to the team at Red Canary (@redcanaryco) for great work on 'Atomic Red Team'.  
Atomic Red Team is a library of tests based on the MITRE ATT&CK&reg; techniques that model adversary behavior, and are used by MATE to populate techniques for testing. To the team at MITRE  
keep up the great work!              

# Yaml configuration
For the most part the yaml files are very similar to Atomic Red Team's. However, in order to provide automated execution
for the Windows platform some modifications have been made. Each yaml can contain numerous different executor commands.  
Below is an example of T1007 and explanation of the different sections:  

---
attack_technique: T1007 **<-- No change from Atomics**  
display_name: System Service Discovery **<-- No change from Atomics**  
tactic: Discovery **<-- Added**  
description: Adversaries may try to get information about registered services. Commands that may obtain information about services using operating system utilities are "sc," "tasklist /svc" using Tasklist, and "net start" using Net.**<-- Added**  

atomic_tests:  
- name: Enumerate system services **<-- Some techniques updated with information**  
  description: |  
    Identify system services cmd **<-- Some techniques updated with information**  
    
  supported_platforms: **<-- Consolidated supported platforms**  
    - windows  

  executor_cmd: **<-- Created numerous executor branches**  
  **executor_cmd (cmd), executor_pwr (PowerShell), executor_nix (Linux/Unix/MacOS), executor_man (manual testing)**  
  ***This was required in order to breakout individual testing commands for automation**  
    name: command_prompt  
    command: |  
      tasklist.exe /v  
      sc query  
      sc query state= all  
      sc start bthserv  
      sc stop bthserv  
      wmic service where displayname="Carbon Black Sensor" get name  
