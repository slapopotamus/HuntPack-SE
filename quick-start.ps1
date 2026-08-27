[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Pause-HuntPack { [void](Read-Host 'Press Enter to continue') }

function Copy-HuntPrompt {
  param([Parameter(Mandatory)][string]$Text)
  try {
    Set-Clipboard -Value $Text -ErrorAction Stop
    return $true
  } catch {
    return $false
  }
}

function Show-Prompt {
  param([Parameter(Mandatory)][string]$Text)
  Clear-Host
  $copied = Copy-HuntPrompt $Text
  if ($copied) { Write-Host 'Copied to clipboard:' -ForegroundColor Green }
  else { Write-Host 'Clipboard unavailable. Copy this prompt manually:' -ForegroundColor Yellow }
  Write-Host "`n  $Text`n"
  Write-Host 'Paste it into Claude Code or Codex opened on this folder.'
  if (-not (Test-Path -LiteralPath 'TECH_STACK.md')) {
    Write-Host 'No stack is configured, so the hunt will run in General mode.'
  }
  Pause-HuntPack
}

function Open-LocalFile {
  param([Parameter(Mandatory)][string]$Path)
  $resolved = (Resolve-Path -LiteralPath $Path).Path
  if ($IsWindows -or $env:OS -eq 'Windows_NT') { Start-Process -FilePath $resolved; return }
  if ($IsMacOS) { & open $resolved; return }
  & xdg-open $resolved
}

function Initialize-Library {
  # index.html is local-only and Git-ignored, so a fresh clone starts without one.
  if (Test-Path -LiteralPath 'index.html') { return $true }
  $template = Join-Path 'dist' 'index.template.html'
  if (-not (Test-Path -LiteralPath $template)) { return $false }
  Copy-Item -LiteralPath $template -Destination 'index.html'
  return $true
}

function Test-Install {
  $checks = [ordered]@{
    'Codex hunt skill' = Test-Path -LiteralPath '.agents\skills\huntpack-agent-local\SKILL.md'
    'Claude hunt skill' = Test-Path -LiteralPath '.claude\skills\huntpack-agent-local\SKILL.md'
    'Local library' = Initialize-Library
    'Pack directory' = Test-Path -LiteralPath 'packs'
  }
  $python = Get-Command python -ErrorAction SilentlyContinue
  if (-not $python) { $python = Get-Command python3 -ErrorAction SilentlyContinue }
  if (-not $python) { $python = Get-Command py -ErrorAction SilentlyContinue }
  $checks['Python 3 launcher'] = [bool]$python
  Clear-Host
  Write-Host 'HuntPack Local preflight' -ForegroundColor Cyan
  foreach ($item in $checks.GetEnumerator()) {
    Write-Host ("  [{0}] {1}" -f ($(if ($item.Value) { 'OK' } else { 'MISSING' }), $item.Key))
  }
  Write-Host "`nPython is required for the static validator suite, not for opening existing HTML packs."
  Pause-HuntPack
}

while ($true) {
  Clear-Host
  Write-Host '================================================================'
  Write-Host '                       HUNTPACK LOCAL' -ForegroundColor Cyan
  Write-Host '                  Claude Code + OpenAI Codex'
  Write-Host '================================================================'
  Write-Host 'No technology stack is required. Choose a hunt and start.'
  Write-Host ''
  Write-Host '  1. Hunt a specific threat, actor, malware, campaign, CVE, or URL'
  Write-Host '  2. Auto-pick broadly relevant current threats'
  Write-Host '  3. Open my HuntPack library'
  Write-Host '  4. Advanced: configure or update my technology stack'
  Write-Host '  5. Show Claude Code / Codex instructions'
  Write-Host '  6. Check this installation'
  Write-Host '  7. Exit'
  $choice = Read-Host 'Choose 1-7'

  switch ($choice) {
    '1' {
      $target = Read-Host 'Enter a threat, actor, malware, campaign, CVE, vulnerability, or intel URL'
      if ([string]::IsNullOrWhiteSpace($target)) { continue }
      Show-Prompt "Build a local hunt pack for $target"
    }
    '2' { Show-Prompt 'Run the local HuntPack auto scan' }
    '3' {
      if (Initialize-Library) { Open-LocalFile 'index.html' }
      else { Write-Host 'index.html and dist\index.template.html are both missing. Re-clone or re-extract the kit.' -ForegroundColor Red; Pause-HuntPack }
    }
    '4' {
      Clear-Host
      Write-Host 'Technology-stack scoping is optional and advanced.'
      Write-Host '  1. Copy a guided setup request'
      Write-Host '  2. Create or edit TECH_STACK.md manually'
      Write-Host '  3. Return'
      $advanced = Read-Host 'Choose 1-3'
      if ($advanced -eq '1') { Show-Prompt 'Configure my HuntPack local technology stack' }
      elseif ($advanced -eq '2') {
        if (-not (Test-Path -LiteralPath 'TECH_STACK.md')) {
          Copy-Item -LiteralPath 'TECH_STACK.example.md' -Destination 'TECH_STACK.md'
        }
        if ($IsWindows -or $env:OS -eq 'Windows_NT') { Start-Process notepad.exe -ArgumentList 'TECH_STACK.md' }
        elseif ($env:EDITOR) { & $env:EDITOR 'TECH_STACK.md' }
        else { Write-Host 'Edit TECH_STACK.md with your preferred editor.'; Pause-HuntPack }
      }
    }
    '5' {
      Clear-Host
      Write-Host 'Open this extracted folder as the project/working directory.'
      Write-Host ''
      Write-Host 'Natural language works in both:'
      Write-Host '  Build a local hunt pack for Scattered Spider'
      Write-Host '  Build a local hunt pack for CVE-2026-XXXXX'
      Write-Host '  Run the local HuntPack auto scan'
      Write-Host ''
      Write-Host 'Explicit invocation:'
      Write-Host '  Claude Code: /huntpack-agent-local'
      Write-Host '  Codex:       $huntpack-agent-local'
      Write-Host ''
      Write-Host 'Output: packs\YYYY-MM\ and index.html. Nothing is published.'
      Pause-HuntPack
    }
    '6' { Test-Install }
    '7' { break }
  }
  if ($choice -eq '7') { break }
}
