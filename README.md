# MATE
MITRE ATT&amp;CK&reg; Technique Emulation - Version: 1.0 

MATE will iterate over modified Atomic Red Team yaml files and create objects for each test. 
The objects will allow for automating execution of MITRE ATT&CK&reg; techniques to test defenses.

License: https://opensource.org/licenses/BSD-3-Clause

Required Dependencies: powershell-yaml, Install-Module powershell-yaml https://github.com/cloudbase/powershell-yaml

Optional Dependencies: Atomic Red Team yaml files https://github.com/redcanaryco/atomic-red-team/tree/master/atomics
*Atomic files have been modified to separate test types (CMD, PowerShell, Nix, Manual). Currently test limited to Windows only.

# Information
Menu driven Powershell application  
TestDir - Local directory containing tests (starting directory will be recursed)  
OutDir - Local output directory for capturing test evidence (command ran along with PID)  
*File will be created for each different command (Ex. sc.exe --> sc.txt)

