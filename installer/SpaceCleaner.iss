; Inno Setup Script for SpaceCleaner
[Setup]
AppId={{8A4F6E6D-0537-4DF1-9E52-2D9D7D96D0F7}
AppName=释放空间助手
AppVersion=1.0.0
AppPublisher=SpaceCleaner Team
DefaultDirName={autopf}\SpaceCleaner
DefaultGroupName=释放空间助手
OutputDir=..\release\installer
OutputBaseFilename=SpaceCleaner_Setup_1.0.0
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\SpaceCleaner.exe

[Languages]
Name: "chinesesimp"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "..\release\SpaceCleaner_Portable\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autodesktop}\释放空间助手"; Filename: "{app}\SpaceCleaner.exe"
Name: "{autoprograms}\释放空间助手"; Filename: "{app}\SpaceCleaner.exe"

[Run]
Filename: "{app}\SpaceCleaner.exe"; Description: "立即运行释放空间助手"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; 保守卸载策略：不删除用户隔离目录（通常在用户目录），仅清理安装目录。
Type: filesandordirs; Name: "{app}"
