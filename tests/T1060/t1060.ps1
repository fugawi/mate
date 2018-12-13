$TargetFile = "<user dir>\mate\tests\t1060\HelloWorld.bat"
$ShortcutFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\Notepad.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TargetFile
$Shortcut.Save()

Remove-Item -Path $ShortcutFile -Force