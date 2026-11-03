# MCP Dev Kit — goose 는 srt 샌드박스 안에서만 실행되게 (P3 상: 샌드박스를 거치지 않는 실행을 PC 관리 도구가 막음)
# 관리자 PowerShell 에서, mcp-test 를 설치한 PC 마다(또는 대표 PC 에서 만든 XML 을 GPO·Intune 으로) 실행한다.
#   powershell -ExecutionPolicy Bypass -File applocker-goose.ps1 -User <개발자 계정 또는 그룹>   [-Apply]
# 하는 일 (해시 규칙 — 키트를 새로 설치·업데이트하면 다시 실행):
#   · goose.exe = 개발자 계정(-User)에게 '거부' — 직접 띄우면 막힘. 거부는 허용보다 앞선다(관리자 계정이어도 막힘)
#     샌드박스는 goose 를 별도 계정(srt-sandbox)으로 실행하므로 이 거부에 걸리지 않는다
#     (-User 에 Users 같은 넓은 그룹을 주면 srt-sandbox 도 들어 있어 샌드박스까지 막힌다 — 개발자 계정·개발자 그룹을 준다)
#   · 이 PC 에 실행 파일(Exe) 규칙이 아직 없으면 '모든 사용자 모두 허용'을 함께 넣는다 — 다른 프로그램은 지금처럼 돈다
#     이미 회사 AppLocker 정책이 있으면 거부 규칙만 합친다(회사 정책을 느슨하게 만들지 않음)
# -Apply 없이 실행하면 정책 XML 만 만들고, 개발자 계정·샌드박스 계정으로 goose.exe 가 허용되는지 시험 결과를 보여 준다.
param([Parameter(Mandatory = $true)][string]$User, [string]$HomeName = $User, [switch]$Apply)
$ErrorActionPreference = 'Stop'
$Dir = Join-Path (Join-Path 'C:\Users' $HomeName) 'AppData\Local\mcp-dev-kit'
$Goose = Get-ChildItem -Path $Dir -Recurse -Filter goose.exe | Select-Object -First 1
if (-not $Goose) { throw "$Dir 에서 goose.exe 를 찾지 못했습니다 (mcp-test 를 먼저 설치 — 다른 폴더면 -HomeName <사용자 폴더 이름>)" }
$Sid = (New-Object Security.Principal.NTAccount($User)).Translate([Security.Principal.SecurityIdentifier]).Value
$SandboxSid = (New-Object Security.Principal.NTAccount('srt-sandbox')).Translate([Security.Principal.SecurityIdentifier]).Value
if ($Sid -in @('S-1-1-0', 'S-1-5-32-545', 'S-1-5-11', 'S-1-5-4')) { throw "$User 는 srt-sandbox 까지 담는 넓은 그룹입니다 — 개발자 계정이나 개발자 그룹을 주세요" }

$h = Get-AppLockerFileInformation -Path $Goose.FullName
$hash = $h.Hash.HashDataString; $len = (Get-Item $Goose.FullName).Length
$hasExeRules = [bool]((Get-AppLockerPolicy -Effective).RuleCollections | Where-Object { $_.RuleCollectionType -eq 'Exe' -and $_.Count -gt 0 })
$allowAll = if ($hasExeRules) { '' } else { @"
    <FilePathRule Id="$([guid]::NewGuid())" Name="MCP Dev Kit — (규칙이 없던 PC) 모든 사용자 모두 허용" Description="MCP Dev Kit" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions></FilePathRule>
"@ }
$xml = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
$allowAll    <FileHashRule Id="$([guid]::NewGuid())" Name="MCP Dev Kit — goose 직접 실행 거부 (샌드박스 안에서만)" Description="MCP Dev Kit" UserOrGroupSid="$Sid" Action="Deny">
      <Conditions><FileHashCondition><FileHash Type="SHA256" Data="$hash" SourceFileName="$($Goose.Name)" SourceFileLength="$len" /></FileHashCondition></Conditions>
    </FileHashRule>
  </RuleCollection>
</AppLockerPolicy>
"@
$out = Join-Path $env:TEMP 'mcp-dev-kit-applocker.xml'
[IO.File]::WriteAllText($out, $xml, [Text.Encoding]::Unicode)
Write-Host "정책 XML: $out  (이 PC 에 실행 파일 규칙 $(if ($hasExeRules) { '있음 — 거부 규칙만 합침' } else { '없음 — 모두 허용 + 거부' }))"

# 시험: 같은 정책에서 개발자 · 샌드박스 계정이 goose.exe 를 실행할 수 있나
$test = if ($hasExeRules) { Join-Path $env:TEMP 'mcp-dev-kit-applocker-merged.xml' } else { $out }
if ($hasExeRules) {   # 회사 정책 + 거부 규칙을 합친 결과로 시험
  $merged = [xml](Get-AppLockerPolicy -Effective -Xml)
  $mine = [xml]$xml
  $exe = $merged.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'Exe'
  $exe.AppendChild($merged.ImportNode($mine.AppLockerPolicy.RuleCollection.FileHashRule, $true)) | Out-Null
  $merged.Save($test)
}
foreach ($who in @($User, 'srt-sandbox')) {
  Test-AppLockerPolicy -XmlPolicy $test -Path $Goose.FullName -User $who |
    ForEach-Object { Write-Host ("{0,-14} {1,-14} {2}" -f $who, $_.PolicyDecision, (Split-Path -Leaf $_.FilePath)) }
}
if ($Apply) {
  Set-AppLockerPolicy -XmlPolicy $out -Merge
  # AppIDSvc 시작 유형은 윈도우가 보호해 바꿀 수 없다(접근 거부) — 정책이 있으면 윈도우가 알아서 띄운다. 지금 바로 켜기만 한다
  Start-Service AppIDSvc
  Write-Host "적용했습니다 (AppIDSvc 시작). $User 는 goose.exe 를 직접 실행할 수 없고, mcp-test(샌드박스)로만 실행됩니다."
}
