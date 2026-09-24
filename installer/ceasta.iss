; ceasta installer (Inno Setup 6)
;
; build the files first, then compile this script:
;   cmake -S . -B build && cmake --build build --config Release
;   cmake --install build --config Release --prefix dist\ceasta
;   iscc /DAppVersion=0.6.0 installer\ceasta.iss
; the setup exe lands in dist\

#ifndef AppVersion
  #define AppVersion "0.6.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\dist\ceasta"
#endif
#ifndef OutputDir
  #define OutputDir "..\dist"
#endif

[Setup]
AppId={{6B0B7E54-3C52-4F2A-9E5B-CEA57A010060}
AppName=ceasta
AppVersion={#AppVersion}
AppVerName=ceasta {#AppVersion}
AppPublisher=ceasta
AppPublisherURL=https://github.com/ngwg/ceasta
AppSupportURL=https://github.com/ngwg/ceasta/issues
AppUpdatesURL=https://github.com/ngwg/ceasta/releases
VersionInfoVersion={#AppVersion}
DefaultDirName={autopf}\ceasta
DefaultGroupName=ceasta
DisableProgramGroupPage=yes
; installs for the current user without admin rights, the user can pick all users instead
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=commandline dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutputDir}
OutputBaseFilename=ceasta-{#AppVersion}-setup
SetupIconFile=..\src\ceasta.ico
UninstallDisplayIcon={app}\ceasta.exe
UninstallDisplayName=ceasta {#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ChangesEnvironment=yes
CloseApplications=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "contextmenu"; Description: "Add ""Open with ceasta"" to the right-click menu of .exe, .dll and .sys files"; GroupDescription: "Shell integration:"
Name: "addtopath"; Description: "Add the install folder to PATH (for ceasta-cli)"; GroupDescription: "Shell integration:"; Flags: unchecked

[Files]
Source: "{#SourceDir}\ceasta.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\ceasta-cli.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\plugins\*"; DestDir: "{app}\plugins"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\CHANGELOG.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\THIRD_PARTY_NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\ceasta"; Filename: "{app}\ceasta.exe"; Comment: "disassembler and debugger"
Name: "{autodesktop}\ceasta"; Filename: "{app}\ceasta.exe"; Tasks: desktopicon

[Registry]
; HKA is HKCU for a per user install and HKLM for an all users install
Root: HKA; Subkey: "Software\Classes\SystemFileAssociations\.exe\shell\ceasta"; ValueType: string; ValueName: ""; ValueData: "Open with ceasta"; Tasks: contextmenu; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\SystemFileAssociations\.exe\shell\ceasta"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\ceasta.exe,0"; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\SystemFileAssociations\.exe\shell\ceasta\command"; ValueType: string; ValueName: ""; ValueData: """{app}\ceasta.exe"" ""%1"""; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\SystemFileAssociations\.dll\shell\ceasta"; ValueType: string; ValueName: ""; ValueData: "Open with ceasta"; Tasks: contextmenu; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\SystemFileAssociations\.dll\shell\ceasta"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\ceasta.exe,0"; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\SystemFileAssociations\.dll\shell\ceasta\command"; ValueType: string; ValueName: ""; ValueData: """{app}\ceasta.exe"" ""%1"""; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\SystemFileAssociations\.sys\shell\ceasta"; ValueType: string; ValueName: ""; ValueData: "Open with ceasta"; Tasks: contextmenu; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\SystemFileAssociations\.sys\shell\ceasta"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\ceasta.exe,0"; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\SystemFileAssociations\.sys\shell\ceasta\command"; ValueType: string; ValueName: ""; ValueData: """{app}\ceasta.exe"" ""%1"""; Tasks: contextmenu

[Run]
Filename: "{app}\ceasta.exe"; Description: "{cm:LaunchProgram,ceasta}"; Flags: nowait postinstall skipifsilent

[Code]
// PATH handling for the "addtopath" task. the entry is removed again on uninstall.
const
  UserEnvKey = 'Environment';
  MachineEnvKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

function EnvRoot: Integer;
begin
  if IsAdminInstallMode then
    Result := HKEY_LOCAL_MACHINE
  else
    Result := HKEY_CURRENT_USER;
end;

function EnvKey: String;
begin
  if IsAdminInstallMode then
    Result := MachineEnvKey
  else
    Result := UserEnvKey;
end;

procedure AddToPath(Dir: String);
var
  Paths: String;
begin
  if not RegQueryStringValue(EnvRoot, EnvKey, 'Path', Paths) then
    Paths := '';
  if Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Paths) + ';') > 0 then
    exit;
  if (Paths <> '') and (Copy(Paths, Length(Paths), 1) <> ';') then
    Paths := Paths + ';';
  RegWriteExpandStringValue(EnvRoot, EnvKey, 'Path', Paths + Dir);
end;

procedure RemoveFromPath(Dir: String);
var
  Paths: String;
  P: Integer;
begin
  if not RegQueryStringValue(EnvRoot, EnvKey, 'Path', Paths) then
    exit;
  Paths := ';' + Paths + ';';
  P := Pos(';' + Uppercase(Dir) + ';', Uppercase(Paths));
  if P = 0 then
    exit;
  Delete(Paths, P, Length(Dir) + 1);
  Paths := Copy(Paths, 2, Length(Paths) - 2);
  RegWriteExpandStringValue(EnvRoot, EnvKey, 'Path', Paths);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('addtopath') then
    AddToPath(ExpandConstant('{app}'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveFromPath(ExpandConstant('{app}'));
end;
