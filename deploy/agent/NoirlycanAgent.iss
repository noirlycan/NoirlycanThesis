; Build with Inno Setup 6.3+ after the single-file Agent has been built.
#ifndef AppVersion
  #define AppVersion "0.3.0"
#endif

[Setup]
AppId={{7AE6BE61-5D8E-4A89-928F-625045776054}
AppName=Noirlycan Agent
AppVersion={#AppVersion}
DefaultDirName={autopf}\Noirlycan Agent
DefaultGroupName=Noirlycan Agent
DisableProgramGroupPage=yes
OutputDir=..\..\dist
OutputBaseFilename=NoirlycanAgentSetup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
UninstallDisplayIcon={app}\NoirlycanAgent.exe
AppMutex=Local\NoirlycanAgentDesktop
CloseApplications=no
RestartApplications=no

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "..\..\dist\NoirlycanAgent.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Noirlycan Agent"; Filename: "{app}\NoirlycanAgent.exe"
Name: "{commondesktop}\Noirlycan Agent"; Filename: "{app}\NoirlycanAgent.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\NoirlycanAgent.exe"; Description: "Open Noirlycan Agent"; Flags: nowait postinstall skipifsilent runascurrentuser
