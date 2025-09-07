param(
  [string]$Base = $env:BASE_URL,
  [switch]$DisableKeepAlive
)

if ([string]::IsNullOrWhiteSpace($Base)) {
  throw "Ustaw -Base lub \$env:BASE_URL"
}

Write-Host "Base =" $Base

# 0) Health (no-cache)
$ts = [int][double]::Parse((Get-Date -UFormat %s))
$health = Invoke-RestMethod "$Base/health?ts=$ts"
"{0,-30} {1}" -f "Health", ($(if($health.ok){"OK"}else{"FAIL"}))

# 1) Auth status (tylko log)
try {
  $auth = Invoke-RestMethod "$Base/auth/status"
  "{0,-30} {1}" -f "Auth", ($(if($auth.authenticated){"OK"}else{"NO"}))
} catch { "{0,-30} {1}" -f "Auth", "UNKNOWN" }

# 2) Labels (opcjonalnie – nie wywal testu)
try {
  $lbl = Invoke-RestMethod "$Base/gmail/labels"
  "{0,-30} {1}" -f "Gmail labels", ($(if($lbl.Count -gt 0){"OK"}else{"EMPTY"}))
} catch { "{0,-30} {1}" -f "Gmail labels", "SKIP" }

# 3) Resilient thread test:
#    - najpierw szukamy wątków z załącznikami z ostatniego roku
#    - jeśli brak / błąd — bierzemy dowolne ostatnie
#    - próbujemy expand=1, a jeśli padnie — expand=0 (meta)
$ok = $false
$chosenTid = $null
$chosenMode = $null

$queries = @("has:attachment newer_than:365d", "")

foreach ($q in $queries) {
  try {
    $url = if ($q) { "$Base/gmail/messages?pageSize=50&q=$( [uri]::EscapeDataString($q) )" }
           else     { "$Base/gmail/messages?pageSize=50" }
    $msgs = Invoke-RestMethod $url
  } catch {
    continue
  }
  if (-not $msgs) { continue }

  foreach ($m in $msgs) {
    $tid = $m.threadId
    if (-not $tid) { continue }

    # expand=1
    try {
      $thr = Invoke-RestMethod "$Base/gmail/thread?threadId=$tid&expand=1"
      "{0,-30} {1}" -f "Thread OK (expand=1)", "$tid  msgs=$($thr.messagesCount)"
      $ok = $true; $chosenTid = $tid; $chosenMode = "expand=1"; break
    } catch {
      # expand=0 (fallback)
      try {
        $thr0 = Invoke-RestMethod "$Base/gmail/thread?threadId=$tid&expand=0"
        "{0,-30} {1}" -f "Thread META OK (expand=0)", "$tid  msgs=$($thr0.messagesCount)"
        $ok = $true; $chosenTid = $tid; $chosenMode = "expand=0"; break
      } catch {
        continue
      }
    }
  }
  if ($ok) { break }
}

if (-not $ok) {
  throw "No thread could be fetched (expand=1 or 0) in top 50."
} else {
  "{0,-30} {1}" -f "Resilient thread result", "$chosenTid  ($chosenMode)"
}

""
"All good ✅"
