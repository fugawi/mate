<#
.SYNOPSIS
MATE will iterate over Atomic Red Team yaml files and create objects for each test. 
The objects will allow for automating execution of MITRE ATT&CK Techniques to test defenses.

Author: Steve Motts @Fugawi72
Special Thanks: Casey Smith @subTee & Red Canary @redcanaryco

License: https://opensource.org/licenses/BSD-3-Clause
Required Dependencies: powershell-yaml , Install-Module powershell-yaml #https://github.com/cloudbase/powershell-yaml
Optional Dependencies: Atomic Red Team yaml files
Version: 1.0

.DESCRIPTION
Create Atomic Tests from yaml files described in Atomic Red Team.
https://github.com/redcanaryco/atomic-red-team

.PARAMETER AtomicFP
Required: Local path to the atomics folder
.PARAMETER OutputFP
Required: Local path to the output of atomics test
Each technique captured in its own file containing Date, Command Executed, PID
Information can be used to validate security technologies detecting techniques

.NOTES
Currently Atomic Red Team test applying to Windows OS and can be initiated from command line are supported.

.LINK
Github repo: https://github.com/fugawi/mate

#>

# Validates working directories for Atomics test and Output
# Loads Atomics yaml files into hashtable
function Invoke-Loadtests() {
	Write-Host "`nSet test directory: " -NoNewLine -Foreground Magenta
	$AtomicFP = Read-Host
	if ([string]::IsNullOrEmpty($AtomicFP)) {
		Return
	}	
	if (-Not (Test-Path $AtomicFP)) {
		Write-Host	"Directory not found, no test loaded!" -Foreground Red
		Start-Sleep 2
		Return
	}
	Write-Host "`nSet output directory: " -NoNewLine -Foreground Magenta
	$OutputFP = Read-Host
	if ([string]::IsNullOrEmpty($OutputFP)) {
		Return
	}	
	if (-Not (Test-Path $OutputFP)) {
		Write-Host	"Output directory not found!" -Foreground Red
		Start-Sleep 2
		Return
	}	
	Write-Host "`nAtomic Test Directory --> " $AtomicFP -Foreground Green
	Write-Host "Searching for *.yml or *.yaml extensions`n" -Foreground Yellow
	try {
		Get-Childitem $AtomicFP -Recurse -Include *.yml, *.yaml -File -ErrorAction Stop |
		ForEach-Object {
			$currentTechnique = [System.IO.Path]::GetFileNameWithoutExtension($_.FullName)
			Write-Host "++ Loading Atomic Test Technique --> "$currentTechnique -Foreground Green
			$parsedYaml = Get-Content -Raw $_.FullName | ConvertFrom-Yaml -Ordered
			#$parsedYaml = (ConvertFrom-Yaml (Get-Content $_.FullName -Raw))
			$AtomicTests.Add($currentTechnique, $parsedYaml)
		}
	} catch  [System.Exception] {
		$errmes = $_.Exception
		Write-Host "Could not find item!"$errmes -Foreground Red
		Return
	}
	Write-Host "++ Loading complete`n" -Foreground Green
	Write-Host "Press any key to continue" -Foreground Yellow
	$a = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
	if ($currentTechnique -eq $null) {
		Write-Host "No techniques found!" -Foreground Red
		Start-Sleep 2
	}
	return $AtomicFP, $OutputFP, $currentTechnique
}

# List all loaded Atomics test (TCode, display name, desc., technique 
function Get-Alltests($values) {
	# Check Atomic directory is set
	try { $val = Test-Path $values[0]
		foreach ($techCode in $AtomicTests.keys) {
			$counter++
			Write-Host "`nTechnique: " -NoNewLine -ForegroundColor Yellow
			Write-Host $AtomicTests.$techCode.display_name -ForegroundColor Green
			Write-Host "ID: " -NoNewLine -ForegroundColor Yellow
			Write-Host $AtomicTests.$techCode.attack_technique #-ForegroundColor Cyan
			Write-Host "Tactic: " -NoNewLine -ForegroundColor Yellow
			Write-Host $AtomicTests.$techCode.tactic #-ForegroundColor Cyan
			Write-Host "Platform: " -NoNewLine -ForegroundColor Yellow
			Write-Host $AtomicTests.$techCode.atomic_tests.supported_platforms #-ForegroundColor Cyan
			Write-Host "Description: " -NoNewLine -ForegroundColor Yellow
			Write-Host $AtomicTests.$techCode.description #-ForegroundColor Cyan
			if ($counter -ge 10) {
				Write-Host "`nPress any key to continue listing tests" -ForegroundColor Yellow
				$a = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				$counter = 0
			}
		}
		Write-Host "`nPress any key to continue" -Foreground Yellow
		$a = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
	} catch {
		Write-Host "`nTechniques Not Loaded!" -Foreground Red
		Start-Sleep 2
	}	
}

# List specific test (TCode, display name, technique
function Get-Techtest($values) {
	Write-Host "`nPlease enter specific technique code (Ex. T1007): " -NoNewLine -ForegroundColor Magenta
	$techCode = Read-Host
	if ($AtomicTests.$techCode) {
		Write-Host "`nTechnique: " -NoNewLine -ForegroundColor Yellow
		Write-Host $AtomicTests.$techCode.display_name -ForegroundColor Green
		Write-Host "ID: " -NoNewLine -ForegroundColor Yellow
		Write-Host $AtomicTests.$techCode.attack_technique
		Write-Host "Tactic: " -NoNewLine -ForegroundColor Yellow
		Write-Host $AtomicTests.$techCode.tactic 
		Write-Host "Platform: " -NoNewLine -ForegroundColor Yellow
		Write-Host $AtomicTests.$techCode.atomic_tests.supported_platforms
		Write-Host "Description: " -NoNewLine -ForegroundColor Yellow
		Write-Host $AtomicTests.$techCode.description
		Write-Host "`nTests:`n" -ForegroundColor Yellow
		if ($AtomicTests.$techCode.atomic_tests.executor_cmd.command) {
			Write-Host "Windows Command Line" -ForegroundColor Yellow
			foreach ($atest in $AtomicTests.$techCode.atomic_tests.executor_cmd.command -split "\n") {
				Write-Host $atest -ForegroundColor Green
			}
		}	
		if ($AtomicTests.$techCode.atomic_tests.executor_pwr.command) {
			Write-Host "Windows Powershell" -ForegroundColor Yellow
			foreach ($atest in $AtomicTests.$techCode.atomic_tests.executor_pwr.command -split "\n") {
				Write-Host $atest -ForegroundColor Green
			}
		}	
		if ($AtomicTests.$techCode.atomic_tests.executor_nix.command) {
			Write-Host "MacOS, Linux, Unix" -ForegroundColor Yellow
			foreach ($atest in $AtomicTests.$techCode.atomic_tests.executor_nix.command -split "\n") {
				Write-Host $atest -ForegroundColor Green
			}
		}
		if ($AtomicTests.$techCode.atomic_tests.executor_man.command) {
			Write-Host "Manual" -ForegroundColor Yellow
			foreach ($atest in $AtomicTests.$techCode.atomic_tests.executor_man.command -split "\n") {
				Write-Host $atest -ForegroundColor Green
			}
		}			
	Write-Host "`nPress any key to continue" -ForegroundColor Yellow
	$a = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")	
	} else {                                                                  
		Write-Host "$techCode - Not Found!" -ForegroundColor Red
		Start-Sleep 2
	}
}

function Invoke-Atests($values) {
	$OutputFP = $values[1]
	Write-Host "`nPlease enter specific technique code (Ex. T1007): " -NoNewLine -Foreground Magenta
	$technum = Read-Host
	if ($AtomicTests.$technum) {
		Write-Host "`nListing $technum MITRE ATT@CK Technique & Description`n"  -Foreground Green
		Write-Host $technum $AtomicTests.$technum.display_name "`n" -Foreground Magenta
		if ($AtomicTests.$technum.atomic_tests.executor_cmd) {
			Write-Host $AtomicTests.$technum.atomic_tests.executor_cmd.name -Foreground Cyan 
			if ($AtomicTests.$technum.atomic_tests.executor_cmd.name.Contains('command_prompt')) {
				foreach ($atest in $AtomicTests.$technum.atomic_tests.executor_cmd.command -split "\n") {
					if (-Not ([string]::IsNullOrEmpty($atest))) {
						Write-Host "Invoking Test --> " $atest -Foreground Green
						$command,$argument = $atest.split(" ",2)
						$ProcessDate = Get-Date -Format g
						if (-Not (Test-Path "$OutputFP\$command.txt")) {
							$NewFile = New-Item -Path "$OutputFP" -Name "$command.txt" -ItemType "File" -Force
						}
						Write-Output "Date --> $ProcessDate" | Out-File -Append "$OutputFP\$command.txt" 
						Write-Output "Command --> $command $argument" | Out-File -Append "$OutputFP\$command.txt"
						$ProcessOutput = start-process $command -ArgumentList $argument -PassThru -WindowStyle Normal -Wait
						$ProcID = $ProcessOutput.iD
						Write-Output "PID --> $ProcID" | Out-File -Append "$OutputFP\$command.txt"
						Write-Host "Information captured --> $OutputFP\$command.txt`n" -ForegroundColor Green
					}
				}
			}
		}
		if ($AtomicTests.$technum.atomic_tests.executor_pwr) {
			Write-Host "`n"$AtomicTests.$technum.atomic_tests.executor_pwr.name -Foreground Cyan
			if ($AtomicTests.$technum.atomic_tests.executor_pwr.name.Contains('powershell')) {
				foreach ($atest in $AtomicTests.$technum.atomic_tests.executor_pwr.command -split "\n") {
					if (-Not ([string]::IsNullOrEmpty($atest))) {
						Write-Host "Invoking Test --> " $atest -Foreground Green
						$command,$argument = $atest.split(" ",2)
						$ProcessDate = Get-Date -Format g
						#if (-Not (Test-Path "$OutputFP\$command.txt")) {
						#	$NewFile = New-Item -Path "$OutputFP" -Name "$command.txt" -ItemType "File" -Force
						#}
						#Write-Output "Date --> $ProcessDate" | Out-File -Append "$OutputFP\$command.txt" 
						#Write-Output "Command --> $command $argument" | Out-File -Append "$OutputFP\$command.txt"
						#$ProcessOutput = start-process powershell.exe -ArgumentList $atest -PassThru -WindowStyle Hidden -Wait
						#$ProcID = $ProcessOutput.iD
						#Write-Output "PID --> $ProcID" | Out-File -Append "$OutputFP\$command.txt"
						#Write-Host "`nInformation captured --> $OutputFP\$command.txt" -ForegroundColor Green
					}
				}
			}
		}	
		Start-Sleep 2
	} else {
		Write-Host "Technique code not found!" -Foreground Red
		Start-Sleep 2
	}
}


# Menu list all options
function Invoke-Menu {
Write-Host '                                                                              
  ______  __________ __________________
  ___   |/  /___    |___  __/___  ____/
  __  /|_/ / __  /| |__  /   __  __/   
  _  /  / /  _  ___ |_  /    _  /___   
  /_/  /_/   /_/  |_|/_/     /_____/   
' -ForegroundColor Yellow
Write-Host "##########################################################################################################" -ForegroundColor Green
Write-Host "##   MITRE ATT&CK"([char]8482)"Technique Emulation (MATE) - v1.0		                                   	##" -ForegroundColor Green
Write-Host "##   Developed By @Fugawi72                                                                             ##" -ForegroundColor Green
Write-Host "##                                                                                                      ##" -ForegroundColor Green
Write-Host "##   Thanks to Casey Smith (@subTee) for his initial work on 'Invoke-Atomic' which led to the creation  ##" -ForegroundColor Green
Write-Host "##   of MATE. A shoutout to the team at Red Canary (@redcanaryco) for great work on 'Atomic Red Team'.  ##" -ForegroundColor Green
Write-Host "##   Atomic Red Team is a library of tests based on the MITRE ATT&CK"([char]8482)"techniques that model		##" -ForegroundColor Green
Write-Host "##   adversary behavior, and are used by MATE to populate techniques for testing.                       ##" -ForegroundColor Green
Write-Host "##                                                                                                      ##" -ForegroundColor Green
Write-Host "##########################################################################################################" -ForegroundColor Green
Write-Host "##   [1] - Set Working Directories & Load Techniques                                                    ##" -ForegroundColor Yellow
Write-Host "##   [2] - List All Loaded Techniques                                                                   ##" -ForegroundColor Yellow
Write-Host "##   [3] - List Specific Technique & Information                                                        ##" -ForegroundColor Yellow
Write-Host "##   [4] - Invoke Specific Test                                                                         ##" -ForegroundColor Yellow
Write-Host "##   [q] - Quit                                                                                         ##" -ForegroundColor Yellow
Write-Host "##########################################################################################################" -ForegroundColor Yellow
}

# Variables
[System.Collections.HashTable]$AtomicTests = @{}
$counter = 0
Clear-Host

# Main while-loop to repeat script until 'q' is pressed
 do {
	Invoke-Menu
	Write-Host "`nPlease enter your choice: " -NoNewLine -ForegroundColor Magenta
	$result = Read-Host
	switch ($result) {
		1 {$values = Invoke-Loadtests }
		2 {Get-Alltests($values)}
		3 {Get-Techtest ($values)}
		4 {Invoke-Atests ($values)}
		q {Write-Host "Quitting script."; Start-Sleep 1; $quit= $true}
		default {Write-Host "Invalid option selected, please try again."}
	}
	Clear-Host
} while (!$quit)
