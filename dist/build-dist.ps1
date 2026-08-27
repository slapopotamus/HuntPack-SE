[CmdletBinding()]
param(
  [ValidatePattern('^v\d+\.\d+$')]
  [string]$Version = 'v1.10'
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$releaseName = "huntpack-local-kit-$Version"
$workRoot = Join-Path $PSScriptRoot (".build-{0}-{1}-{2}" -f $Version, $stamp, ([guid]::NewGuid().ToString('N').Substring(0, 8)))
$releaseRoot = Join-Path $workRoot $releaseName
$releaseOutput = Join-Path $PSScriptRoot 'releases'
$zip = Join-Path $releaseOutput ("{0}_{1}.zip" -f $releaseName, $stamp)

function Get-TreeDigestMap {
  param([Parameter(Mandatory)][string]$Root)
  $resolved = (Resolve-Path -LiteralPath $Root).Path
  $map = @{}
  Get-ChildItem -LiteralPath $resolved -Recurse -File -Force | ForEach-Object {
    $relative = $_.FullName.Substring($resolved.Length).TrimStart('\', '/').Replace('\', '/')
    $map[$relative] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  }
  return $map
}

function Assert-SkillParity {
  $agents = Get-TreeDigestMap (Join-Path $projectRoot '.agents\skills\huntpack-agent-local')
  $claude = Get-TreeDigestMap (Join-Path $projectRoot '.claude\skills\huntpack-agent-local')
  $all = @($agents.Keys + $claude.Keys | Sort-Object -Unique)
  $drift = @($all | Where-Object {
    -not $agents.ContainsKey($_) -or -not $claude.ContainsKey($_) -or $agents[$_] -ne $claude[$_]
  })
  if ($drift.Count -gt 0) {
    throw "Claude/Codex hunt skill drift detected: $($drift -join ', ')"
  }
}

function Resolve-Python {
  foreach ($name in @('python', 'python3')) {
    $command = Get-Command $name -ErrorAction SilentlyContinue
    if ($command) { return [pscustomobject]@{ Exe = $command.Source; LauncherArg = $null } }
  }
  $py = Get-Command py -ErrorAction SilentlyContinue
  if ($py) { return [pscustomobject]@{ Exe = $py.Source; LauncherArg = '-3' } }
  throw 'Python 3 is required to run the HuntPack validator self-tests.'
}

function Invoke-ValidatorSelfTests {
  $python = Resolve-Python
  $validator = Join-Path $projectRoot '.agents\skills\huntpack-agent-local\scripts\validate_huntpack.py'
  if (-not (Test-Path -LiteralPath $validator)) { throw "Validator orchestrator missing: $validator" }
  $pythonExe = $python.Exe
  if ([string]::IsNullOrEmpty($python.LauncherArg)) {
    & $pythonExe -X utf8 $validator --self-test
  } else {
    $pythonLauncherArg = $python.LauncherArg
    & $pythonExe $pythonLauncherArg -X utf8 $validator --self-test
  }
  if ($LASTEXITCODE -ne 0) { throw 'HuntPack validator self-tests failed.' }
}

function Assert-ReleaseSafe {
  param([Parameter(Mandatory)][string]$Root)
  $forbiddenNames = @('TECH_STACK.md', 'settings.local.json', '.git', 'pipeline-upstream', '.runs')
  foreach ($name in $forbiddenNames) {
    $hit = Get-ChildItem -LiteralPath $Root -Recurse -Force | Where-Object Name -eq $name
    if ($hit) { throw "Leak guard: forbidden artifact found: $name" }
  }

  # Assemble these at runtime so the release builder can scan a copy of itself
  # without matching its own deny-list definitions.
  $privateMarkers = @(
    ('FortiGate' + '-100F'), ('FAC' + '300F'), ('FPR' + '-3105'),
    ('Nasu' + 'ni'), ('Mitel Connect' + ' Director')
  )
  foreach ($marker in $privateMarkers) {
    if (Get-ChildItem -LiteralPath $Root -Recurse -File -Force | Select-String -SimpleMatch $marker -ErrorAction SilentlyContinue) {
      throw "Leak guard: environment marker found: $marker"
    }
  }

  $patterns = @(
    '(?i)\b(?:AKIA|ASIA)[A-Z0-9]{16}\b',
    '(?i)\bgh[pousr]_[A-Za-z0-9]{20,}\b',
    '(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token)\s*[:=]\s*["''][^"'']{8,}',
    '(?i)\bBearer\s+[A-Za-z0-9._-]{20,}',
    '(?i)C:\\Users\\[^\\\s]+\\',
    '(?i)/(?:Users|home)/[^/\s]+/'
  )
  foreach ($file in Get-ChildItem -LiteralPath $Root -Recurse -File -Force) {
    $text = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction SilentlyContinue
    if ($null -eq $text) { continue }
    foreach ($pattern in $patterns) {
      if ($text -match $pattern) { throw "Leak guard: sensitive pattern in $($file.FullName)" }
    }
  }
}

function Write-Manifest {
  param([Parameter(Mandatory)][string]$Root)
  $manifest = Join-Path $Root 'MANIFEST.sha256'
  $resolved = (Resolve-Path -LiteralPath $Root).Path
  $lines = Get-ChildItem -LiteralPath $resolved -Recurse -File -Force |
    Where-Object FullName -ne $manifest |
    Sort-Object FullName |
    ForEach-Object {
      $relative = $_.FullName.Substring($resolved.Length).TrimStart('\', '/').Replace('\', '/')
      "{0}  {1}" -f ((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()), $relative
    }
  Set-Content -LiteralPath $manifest -Value $lines -Encoding utf8NoBOM
}

function New-PortableZip {
  param([Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$Destination)
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [System.IO.Compression.ZipFile]::CreateFromDirectory($Source, $Destination, [System.IO.Compression.CompressionLevel]::Optimal, $false)
}

function Assert-ZipInventory {
  param([Parameter(Mandatory)][string]$Path)
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
  try {
    $entries = @($archive.Entries | ForEach-Object FullName)
    $prefix = "$releaseName/"
    $required = @(
      "${prefix}.agents/skills/huntpack-agent-local/SKILL.md",
      "${prefix}.claude/skills/huntpack-agent-local/SKILL.md",
      "${prefix}AGENTS.md", "${prefix}CLAUDE.md", "${prefix}README.md",
      "${prefix}index.html", "${prefix}packs/.gitkeep", "${prefix}scripts/huntpack.py",
      "${prefix}VERSION", "${prefix}MANIFEST.sha256"
    )
    foreach ($entry in $required) {
      if ($entries -notcontains $entry) { throw "ZIP verification failed: missing $entry" }
    }
    if ($entries | Where-Object { -not $_.StartsWith($prefix, [StringComparison]::Ordinal) }) {
      throw 'ZIP verification failed: archive has more than one top-level root.'
    }
    foreach ($forbidden in @('TECH_STACK.md', 'settings.local.json', '/.git/', 'pipeline-upstream')) {
      if ($entries | Where-Object { $_ -like "*$forbidden*" }) {
        throw "ZIP verification failed: forbidden entry $forbidden"
      }
    }
  } finally {
    $archive.Dispose()
  }
}

if (Test-Path -LiteralPath $zip) { throw "Distribution already exists: $zip" }
New-Item -ItemType Directory -Path $releaseOutput -Force | Out-Null

try {
  Assert-SkillParity
  Invoke-ValidatorSelfTests

  New-Item -ItemType Directory -Path $releaseRoot -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $releaseRoot '.agents\skills') -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $releaseRoot '.claude\skills') -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $releaseRoot 'packs') -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $releaseRoot 'dist') -Force | Out-Null

  Copy-Item -LiteralPath (Join-Path $projectRoot '.agents\skills\huntpack-agent-local') -Destination (Join-Path $releaseRoot '.agents\skills\huntpack-agent-local') -Recurse
  Copy-Item -LiteralPath (Join-Path $projectRoot '.agents\skills\huntpack-local-setup') -Destination (Join-Path $releaseRoot '.agents\skills\huntpack-local-setup') -Recurse
  Copy-Item -LiteralPath (Join-Path $projectRoot '.claude\skills\huntpack-agent-local') -Destination (Join-Path $releaseRoot '.claude\skills\huntpack-agent-local') -Recurse
  Copy-Item -LiteralPath (Join-Path $projectRoot '.claude\skills\huntpack-local-setup') -Destination (Join-Path $releaseRoot '.claude\skills\huntpack-local-setup') -Recurse

  $publicFiles = @('.gitignore', 'AGENTS.md', 'CLAUDE.md', 'INSTALLING-SKILLS.md', 'LICENSE',
    'quick-start.bat', 'quick-start.ps1', 'quick-start.sh', 'QUICKSTART.md', 'README.md',
    'SETUP.md', 'START-HERE.md', 'TECH_STACK.example.md')
  foreach ($name in $publicFiles) {
    Copy-Item -LiteralPath (Join-Path $projectRoot $name) -Destination (Join-Path $releaseRoot $name)
  }
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'index.template.html') -Destination (Join-Path $releaseRoot 'index.html')
  New-Item -ItemType Directory -Path (Join-Path $releaseRoot 'scripts') -Force | Out-Null
  Copy-Item -LiteralPath (Join-Path $projectRoot 'scripts\doctor.py') -Destination (Join-Path $releaseRoot 'scripts\doctor.py')
  Copy-Item -LiteralPath (Join-Path $projectRoot 'scripts\huntpack.py') -Destination (Join-Path $releaseRoot 'scripts\huntpack.py')
  Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $releaseRoot 'dist\build-dist.ps1')
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'index.template.html') -Destination (Join-Path $releaseRoot 'dist\index.template.html')
  New-Item -ItemType File -Path (Join-Path $releaseRoot 'packs\.gitkeep') | Out-Null
  Set-Content -LiteralPath (Join-Path $releaseRoot 'VERSION') -Value $Version -Encoding utf8NoBOM

  Assert-ReleaseSafe $releaseRoot
  Write-Manifest $releaseRoot
  New-PortableZip $workRoot $zip
  Assert-ZipInventory $zip

  $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
  [pscustomobject]@{ Path = $zip; Version = $Version; SHA256 = $hash; Bytes = (Get-Item -LiteralPath $zip).Length }
} finally {
  if (Test-Path -LiteralPath $workRoot) {
    $resolvedWork = [System.IO.Path]::GetFullPath($workRoot)
    $resolvedDist = [System.IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') + '\'
    if (-not $resolvedWork.StartsWith($resolvedDist, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([System.IO.Path]::GetFileName($resolvedWork)).StartsWith('.build-', [StringComparison]::Ordinal)) {
      throw "Refusing to remove unexpected build path: $resolvedWork"
    }
    Remove-Item -LiteralPath $resolvedWork -Recurse -Force
  }
}
