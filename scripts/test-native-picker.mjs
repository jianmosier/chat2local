import assert from 'node:assert/strict';
import { pickFolder, powershell } from '../src/agent/store.mjs';

// Explicit opt-in interactive smoke test. Opens and cancels only its own picker;
// no folder is selected, no policy is changed, no other browser/window is read.
if (!process.argv.includes('--live')) throw new Error('Use --live to briefly open a test-owned Windows picker.');
const abort = new AbortController();
let child; let close;
const dialog = pickFolder({ signal: abort.signal, onSpawn: process => { child = process; close = new Promise(resolve => process.once('close', resolve)); } });
const outcome = dialog.then(path => ({ path }), error => ({ error: error.name, detail: error.message }));
const deadline = setTimeout(() => abort.abort(), 22000);
let visible = false;
try {
  assert.ok(Number.isInteger(child?.pid));
  // UI Automation filters by the exact PID created above before reading UI properties.
  const script = "$ErrorActionPreference='Stop'; Add-Type -AssemblyName UIAutomationClient; Add-Type -AssemblyName UIAutomationTypes; $target=[int][Console]::In.ReadToEnd(); $condition=New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty,$target); $windows=[System.Windows.Automation.AutomationElement]::RootElement.FindAll([System.Windows.Automation.TreeScope]::Children,$condition); $visible=0; foreach($w in $windows){$r=$w.Current.BoundingRectangle; if(-not $w.Current.IsOffscreen -and $r.Width -gt 150 -and $r.Height -gt 100){$visible++}}; @{visibleDialogCount=$visible}|ConvertTo-Json -Compress";
  for (let attempt = 0; attempt < 4 && !visible && !abort.signal.aborted; attempt++) {
    await new Promise(resolve => setTimeout(resolve, 500));
    const state = JSON.parse(await powershell(script, String(child.pid), 5000));
    visible = state.visibleDialogCount > 0;
  }
  if (!visible) console.log(JSON.stringify({ testOwnedPickerPid: child.pid, exited: child.exitCode, outcome: child.exitCode !== null ? await outcome : 'still-running' }));
  assert.ok(visible, 'A real visible picker must exist in the test-owned process.');
  console.log('PASS: real Windows folder dialog observed via PID-filtered UI Automation.');
} finally { abort.abort(); clearTimeout(deadline); await outcome; await close; }
assert.equal((await outcome).error, 'AbortError');
console.log('PASS: cancellation stopped only the test-owned picker; no folder was authorized.');
