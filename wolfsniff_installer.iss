; Inno Setup Script for Wolfsniff v1.0
; This script will package your `--onedir` folder into a professional Setup.exe
; It also automatically executes the Npcap installer during setup!

[Setup]
AppName=Wolfsniff
AppVersion=1.0
AppPublisher=SKECH
UninstallDisplayName=Wolfsniff 1.0
DefaultDirName={pf}\Wolfsniff
DefaultGroupName=Wolfsniff
OutputDir=.\installer_output
OutputBaseFilename=Wolfsniff_Setup_v1.0
Compression=lzma
SolidCompression=yes
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\Wolfsniff_v1.0.exe

[Files]
; 1. Copy the entire PyInstaller onedir folder contents into the Program Files directory
Source: "dist\Wolfsniff_v1.0\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; 2. Bundle the Npcap installer so we can run it automatically!
; IMPORTANT: Download the Npcap installer (e.g. npcap-1.79.exe) and place it in the same folder as this script
Source: "npcap-installer.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Icons]
; Create a Desktop Shortcut
Name: "{autodesktop}\Wolfsniff"; Filename: "{app}\Wolfsniff_v1.0.exe"
; Create a Start Menu Shortcut
Name: "{group}\Wolfsniff"; Filename: "{app}\Wolfsniff_v1.0.exe"

[Run]
; Automatically run the Npcap installer during installation!
Filename: "{tmp}\npcap-installer.exe"; Parameters: "/winpcap_mode=yes"; Flags: waituntilterminated; StatusMsg: "Installing Npcap Network Drivers..."

; Launch Wolfsniff when the installation finishes
Filename: "{app}\Wolfsniff_v1.0.exe"; Description: "Launch Wolfsniff"; Flags: nowait postinstall skipifsilent
