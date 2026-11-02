# MCP Dev Kit 설치 (윈도우) — 포털 다운로드 페이지가 서버 주소·해시를 채워서 내려준다.
# 사용: $env:KIT_TOKEN='<개인 키>'; irm {{PUBLIC}}/download/install.ps1 | iex
$ErrorActionPreference = 'Stop'
$Public = '{{PUBLIC}}'
$File = '{{GOOSE_FILE}}'
$Sha256 = '{{GOOSE_SHA256}}'
if (-not $env:KIT_TOKEN) { throw '포털 다운로드 페이지에서 개인 키를 발급받아 $env:KIT_TOKEN 에 넣어 주세요' }

$Dir = Join-Path $env:LOCALAPPDATA 'mcp-dev-kit'
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
$Zip = Join-Path $Dir $File

Write-Host 'goose 받는 중…'
Invoke-WebRequest -UseBasicParsing -Headers @{ Authorization = "Bearer $env:KIT_TOKEN" } -Uri "$Public/download/files/$File" -OutFile $Zip
if ((Get-FileHash -Algorithm SHA256 $Zip).Hash.ToLower() -ne $Sha256) { Remove-Item $Zip; throw '파일 해시가 맞지 않습니다' }
Expand-Archive -Force -Path $Zip -DestinationPath $Dir
Remove-Item $Zip
$Goose = Get-ChildItem -Path $Dir -Recurse -Filter goose.exe | Select-Object -First 1
if (-not $Goose) { throw 'goose.exe 를 찾지 못했습니다' }

Set-Content -NoNewline -Path (Join-Path $Dir 'token') -Value $env:KIT_TOKEN
$CaPem = @'
{{CA_PEM}}
'@
if ($CaPem.Trim()) {
  # 사내 CA 를 현재 사용자 신뢰 저장소에 등록 (관리자 권한 불필요, 윈도우가 확인 창을 띄운다)
  $Ca = Join-Path $Dir 'kit-ca.pem'
  Set-Content -Path $Ca -Value $CaPem
  Import-Certificate -FilePath $Ca -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
}

$Cmd = @"
@echo off
rem MCP Dev Kit - run goose against the in-house LiteLLM. Arguments go to goose.
set GOOSE_PROVIDER=openai
set GOOSE_MODEL=kit-llm
set OPENAI_HOST=$Public/llm
set /p OPENAI_API_KEY=<"$Dir\token"
set GOOSE_TELEMETRY_OFF=1
set GOOSE_DISABLE_KEYRING=1
if "%~1"=="" ( "$($Goose.FullName)" session ) else ( "$($Goose.FullName)" %* )
"@
Set-Content -Path (Join-Path $Dir 'mcp-test.cmd') -Value $Cmd -Encoding OEM

$UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not ($UserPath -split ';' -contains $Dir)) {
  [Environment]::SetEnvironmentVariable('Path', "$UserPath;$Dir", 'User')
  Write-Host "PATH 에 $Dir 를 추가했습니다. 새 터미널에서 mcp-test 를 실행하세요."
}
Write-Host "설치 완료: $Dir\mcp-test.cmd"
& (Join-Path $Dir 'mcp-test.cmd') --version
