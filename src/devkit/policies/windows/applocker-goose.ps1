# MCP Dev Kit — goose 는 srt 샌드박스 안에서만 실행되게 (P3 상: 샌드박스를 거치지 않는 실행을 PC 관리 도구가 막음)
# 관리자 PowerShell 에서, mcp-test 를 설치한 PC 마다(또는 대표 PC 에서 만든 XML 을 GPO·Intune 으로) 실행한다.
#   powershell -ExecutionPolicy Bypass -File applocker-goose.ps1 -User <개발자 계정>   [-Apply]
# 하는 일 (해시 규칙 — 키트를 새로 설치·업데이트하면 다시 실행):
#   · goose.exe   = srt 샌드박스 사용자 그룹(sandbox-runtime-users)만 실행 허용  → 개발자가 직접 띄우면 막힘
#   · srt-win.exe = 모든 사용자 실행 허용(샌드박스를 여는 쪽)
#   · 윈도우 기본 규칙(Windows · Program Files · 관리자) 그대로
# -Apply 없이 실행하면 정책 XML 만 만들고, 개발자 계정·샌드박스 계정으로 goose.exe 가 허용되는지 시험 결과를 보여 준다.
param([Parameter(Mandatory = $true)][string]$User, [switch]$Apply)
$ErrorActionPreference = 'Stop'
$Dir = Join-Path (Join-Path 'C:\Users' $User) 'AppData\Local\mcp-dev-kit'
$Goose = Get-ChildItem -Path $Dir -Recurse -Filter goose.exe | Select-Object -First 1
$SrtWin = Get-ChildItem -Path (Join-Path $Dir 'srt-bundle') -Recurse -Filter srt-win.exe | Where-Object { $_.FullName -match '\\x64\\' } | Select-Object -First 1
if (-not $Goose -or -not $SrtWin) { throw "$Dir 에서 goose.exe · srt-win.exe 를 찾지 못했습니다 (mcp-test 를 먼저 설치)" }
$Group = (New-Object Security.Principal.NTAccount('sandbox-runtime-users')).Translate([Security.Principal.SecurityIdentifier]).Value

function HashRule($file, $sid, $name) {
  $h = Get-AppLockerFileInformation -Path $file.FullName
  $hash = $h.Hash.HashDataString; $len = (Get-Item $file.FullName).Length
  @"
    <FileHashRule Id="$([guid]::NewGuid())" Name="$name" Description="MCP Dev Kit" UserOrGroupSid="$sid" Action="Allow">
      <Conditions><FileHashCondition><FileHash Type="SHA256" Data="$hash" SourceFileName="$($file.Name)" SourceFileLength="$len" /></FileHashCondition></Conditions>
    </FileHashRule>
"@
}

$xml = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20" Name="(기본) Program Files" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions></FilePathRule>
    <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51" Name="(기본) Windows" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions></FilePathRule>
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2" Name="(기본) 관리자" Description="" UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions></FilePathRule>
$(HashRule $Goose $Group 'MCP Dev Kit goose (샌드박스 안에서만)')
$(HashRule $SrtWin 'S-1-1-0' 'MCP Dev Kit srt-win (샌드박스 여는 쪽)')
  </RuleCollection>
</AppLockerPolicy>
"@
$out = Join-Path $env:TEMP 'mcp-dev-kit-applocker.xml'
[IO.File]::WriteAllText($out, $xml, [Text.Encoding]::Unicode)
Write-Host "정책 XML: $out"

# 시험: 같은 정책에서 개발자 본인 · 샌드박스 계정이 goose.exe 를 실행할 수 있나
foreach ($who in @($User, 'Users', 'srt-sandbox')) {   # Users = 일반(표준) 사용자 그룹으로 시험
  $r = Test-AppLockerPolicy -XmlPolicy $out -Path $Goose.FullName, $SrtWin.FullName -User $who
  $r | ForEach-Object { Write-Host ("{0,-12} {1,-14} {2}" -f $who, $_.PolicyDecision, (Split-Path -Leaf $_.FilePath)) }
}
if ($Apply) {
  Set-AppLockerPolicy -XmlPolicy $out -Merge
  Set-Service AppIDSvc -StartupType Automatic; Start-Service AppIDSvc
  Write-Host '적용했습니다 (AppIDSvc 시작). 표준 사용자는 goose.exe 를 직접 실행할 수 없습니다.'
}
