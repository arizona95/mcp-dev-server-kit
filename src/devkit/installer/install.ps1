# MCP Dev Kit 설치 (윈도우) — 포털 다운로드 페이지가 서버 주소·해시를 채워서 내려준다.
# 사용: $env:KIT_TOKEN='<내려받기 코드>'; irm {{PUBLIC}}/download/install.ps1 | iex   (코드는 30분 동안 설치 파일만 받는다 — PC 에 저장하지 않음)
# 설치되는 것: goose · srt 샌드박스(sandbox-runtime) · mcp-test (실행할 때마다 서버 정책을 받아 srt 안에서 goose 실행)
# irm | iex 는 사용자 터미널 범위에서 돈다 — 설정이 그 터미널에 남지 않게 블록 안에서 실행
& {
$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 은 진행 막대를 그리느라 내려받기가 수십 배 느려진다
$ProgressPreference = 'SilentlyContinue'
$Public = '{{PUBLIC}}'
$File = '{{GOOSE_FILE}}'
$Sha256 = '{{GOOSE_SHA256}}'
$SrtSha256 = '{{SRT_SHA256}}'
$MjsSha256 = '{{MJS_SHA256}}'
$PyShimSha256 = '{{PYSHIM_SHA256}}'
$GateSha256 = '{{GATE_SHA256}}'
if (-not $env:KIT_TOKEN) { throw '포털 다운로드 페이지의 설치 명령을 그대로 붙여 넣어 주세요 (내려받기 코드 포함)' }

# 샌드박스(srt)에 필요한 것: Node 22.12 이상 (윈도우는 그 밖에 추가 설치 없음 — 처음 한 번 관리자 준비 단계만)
$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) { throw 'Node 22.12 이상을 먼저 설치해 주세요 (사내 배포본)' }
# Windows PowerShell 5.1 은 외부 프로그램 인자 속 큰따옴표를 지운다 — JS 안은 작은따옴표만 쓴다
& node -e 'const [a,b]=process.versions.node.split(''.'').map(Number); process.exit(a>22||(a==22&&b>=12)?0:1)'
if ($LASTEXITCODE -ne 0) { throw "Node 22.12 이상이 필요합니다 (지금 $(node --version))" }

# goose.exe 는 Visual C++ 런타임(MSVCP140.dll)이 있어야 뜬다 — 사내 배포본(VC++ 2015-2022 x64 재배포 패키지)
if (-not (Test-Path (Join-Path $env:SystemRoot 'System32\msvcp140.dll'))) { throw 'Visual C++ 2015-2022 x64 런타임을 먼저 설치해 주세요 (사내 배포본 · https://aka.ms/vs/17/release/vc_redist.x64.exe)' }

$Dir = Join-Path $env:LOCALAPPDATA 'mcp-dev-kit'
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
function Get-KitFile($name, $sha) {
  $out = Join-Path $Dir $name
  Invoke-WebRequest -UseBasicParsing -Headers @{ Authorization = "Bearer $env:KIT_TOKEN" } -Uri "$Public/download/files/$name" -OutFile $out
  if ((Get-FileHash -Algorithm SHA256 $out).Hash.ToLower() -ne $sha) { Remove-Item $out; throw "$name 해시가 맞지 않습니다" }
  return $out
}

Write-Host 'goose 받는 중...'
$Zip = Get-KitFile $File $Sha256
Expand-Archive -Force -Path $Zip -DestinationPath $Dir
Remove-Item $Zip
$Goose = Get-ChildItem -Path $Dir -Recurse -Filter goose.exe | Select-Object -First 1
if (-not $Goose) { throw 'goose.exe 를 찾지 못했습니다' }

Write-Host '샌드박스(srt) 받는 중...'
$Tgz = Get-KitFile 'srt-bundle.tgz' $SrtSha256
if (Test-Path (Join-Path $Dir 'srt-bundle')) { Remove-Item -Recurse -Force (Join-Path $Dir 'srt-bundle') }
tar -xzf $Tgz -C $Dir
Remove-Item $Tgz
Get-KitFile 'mcp-test.mjs' $MjsSha256 | Out-Null
# 사람 승인 관문 — 샌드박스 안에서 MCP 앞에 서서 툴 호출마다 mcp-test 에 묻는다
Get-KitFile 'mcp-gate.mjs' $GateSha256 | Out-Null
icacls (Join-Path $Dir 'mcp-gate.mjs') /grant '*S-1-5-32-545:RX' /Q | Out-Null
# 샌드박스 안 파이썬 보정: srt 는 루프백도 허용 포트 범위 밖이면 막아 asyncio(socketpair)가 멈춘다 — 그 범위 안에서 쌍을 만든다
New-Item -ItemType Directory -Force -Path (Join-Path $Dir 'pyshim') | Out-Null
Move-Item -Force (Get-KitFile 'sitecustomize.py' $PyShimSha256) (Join-Path $Dir 'pyshim\sitecustomize.py')
$SrtCli = Join-Path $Dir 'srt-bundle\node_modules\@anthropic-ai\sandbox-runtime\dist\cli.js'
# srt 는 명령을 별도 사용자(srt-sandbox)로 실행한다 — 개인 폴더(AppData)에 둔 srt·goose 를 그 사용자가 읽고 실행할 수 있게
# (Users 읽기·실행만)
foreach ($sub in 'srt-bundle', 'pyshim', (Split-Path -Leaf $Goose.DirectoryName)) { icacls (Join-Path $Dir $sub) /grant '*S-1-5-32-545:(OI)(CI)RX' /T /Q | Out-Null }

Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $Dir 'token')   # 예전 판의 개인 키 파일 — 이제 PC 에 키를 두지 않는다
$CaPem = @'
{{CA_PEM}}
'@
$CaFile = ''
if ($CaPem.Trim()) {
  # 사내 CA 를 현재 사용자 신뢰 저장소에 등록 (관리자 권한 불필요, 윈도우가 확인 창을 띄운다)
  $CaFile = Join-Path $Dir 'kit-ca.pem'
  Set-Content -Path $CaFile -Value $CaPem
  Import-Certificate -FilePath $CaFile -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
}
# Git for Windows(OpenSSL)는 윈도우 신뢰 저장소를 보지 않는다 — 키트 주소에서만 사내 CA 를 쓰게 한다
if ($CaFile -and (Get-Command git -ErrorAction SilentlyContinue)) { git config --global "http.$Public/.sslCAInfo" $CaFile }
@{ public = $Public; dir = $Dir; goose = $Goose.FullName; srt_cli = $SrtCli; ca_bundle = '' } |
  ConvertTo-Json | Set-Content -Path (Join-Path $Dir 'kit.json')

$Cmd = @"
@echo off
rem MCP Dev Kit - fetch the policy from the in-house server on every run and start goose inside the srt sandbox.
if exist "$CaFile" set NODE_EXTRA_CA_CERTS=$CaFile
node "$Dir\mcp-test.mjs" %*
"@
Set-Content -Path (Join-Path $Dir 'mcp-test.cmd') -Value $Cmd -Encoding OEM

$UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not ($UserPath -split ';' -contains $Dir)) {
  [Environment]::SetEnvironmentVariable('Path', "$UserPath;$Dir", 'User')
  Write-Host "PATH 에 $Dir 를 추가했습니다. 새 터미널에서 mcp-test 를 실행하세요."
}
Write-Host "설치 완료: $Dir\mcp-test.cmd"
Write-Host "처음 한 번, 관리자 PowerShell 에서 샌드박스 준비: node `"$SrtCli`" windows-install --proxy-port-range 60080-60143"
& $Goose.FullName --version
}
