# DaHe Logistics

The repository is developed as numbered Loops defined in `DEVELOPMENT_GUIDE.md`.
Loop 9 established the guarded read-only production path. Loop 10 turns that
path into the formal per-user Windows application: one visible Chengfeng tab,
fresh cache-disabled reads, a versioned installer and updater, Schema preflight
and rollback, and bounded local diagnostics. The Ledger is execution evidence;
it does not replace the durable product and development contracts.

Loop 12 converges the operational daily workspace and console shell. Business
date changes clear the previous date immediately and accept only the newest
matching response; manual save confirms every current issue, including an
explicit blank. Daily browser preparation goes directly to `/wayBill` and must
not prepare or query the settlement page. The sidebar shows one backend-owned
Chengfeng connection state, and the operator system view contains diagnostics,
templates and settings only.

Loop 13 makes each new business read one atomic whole run. Platform pagination
only enumerates the authoritative list; details and images are read without
50-item business batches, published once after full reconciliation, and handed
to exactly one offline review Job. The UI binds to the new source Job, shows
`正在离线审核 n/总数`, and appends only the contiguous completed prefix in frozen
waybill order. Old `batch_v1` records remain read-only compatible.

Loop 14 scopes every Chengfeng business identity by contract subject. The
operator can select `山西贵恩博` or `上海晋亿晟` without navigating the idle browser;
the selected subject is verified only when a settlement or daily read starts,
and its tasks, reviews, history, reuse index and reports remain isolated. Schema
`0041_contract_subject_scope` assigns all pre-existing records to Shanxi. The
1.1.4 installer keeps GitHub as the only online source, retains validated resumable
application-ZIP downloads and supports an equally validated local package
import for unstable networks. Its formal GPU add-on is installed and qualified
by the versioned updater; copying the GPU ZIP by hand does not activate it. A
fresh formal installation also copies and verifies every read-only operational
contract declared by its seed marker, so it does not depend on an older data
root that happened to receive those contracts during development or repair.

Loop 18 separates the complete daily candidate snapshot from the formal report
window. New daily reads freeze a configurable candidate range that defaults to
business-day 14:00 through server-now; the workbook independently includes only
effective loading times in `[14:00, next-day 14:00)`. Loading-ticket OCR or a
manual revision is primary, while platform loading time is a blank-cell fallback
for inclusion and ordering. Offline OCR keeps one GPU Worker and gives the other
side of the same vehicle one pairing priority before returning to cross-job
fairness. Schema `0042_daily_capture_range` stores the versioned settings and
frozen task range.

The committed development checkout is the authoritative latest implementation.
Run and verify it only through `.venv\Scripts\python.exe`. An installed build is
a frozen release and is updated only when the user explicitly requests a new
package; development work must never patch the installed directory in place.
Every handoff reports the source HEAD, the executable identity currently bound
to port 8877, and the installed release identity separately.

## Bootstrap

Run from a normal Command Prompt:

```bat
tools\bootstrap.cmd
```

The bootstrap command creates `.venv` with Python 3.12, installs the exact
Python and frontend locks, and runs the authoritative checks. It does not modify
global Python, npm, PowerShell policy, DNS, proxy, or VPN settings.

## Authoritative checks

Run every project check through the project virtual environment:

```powershell
.\.venv\Scripts\python.exe tools\check.py
```

The authoritative command currently runs roughly 3,000 Python tests and can
take more than ten minutes on Windows. Do not treat an outer command timeout as
a test failure or replace the full run with only targeted checks. Loop 13's
narrow preflight is:

```powershell
.\.venv\Scripts\python.exe -m pytest `
  tests\unit\application\chengfeng\test_fast_operational_capture.py `
  tests\unit\application\chengfeng\test_browser_readiness.py `
  tests\unit\application\daily\test_fast_operational_daily_capture.py `
  tests\integration\test_daily_items_api.py `
  tests\integration\test_daily_operational_progress_api.py `
  tests\integration\test_loop8_audit_workflow_repository.py `
  tests\integration\test_loop9_daily_live_execution.py `
  tests\unit\platform\test_loop9_daily_browser_runtime.py `
  tests\unit\platform\test_loop9_live_connector_runtime.py `
  tests\unit\verification\test_loop9_request_audit.py `
  tests\unit\adapters\test_browser_runtime.py -q
npm.cmd --prefix frontend run check
```

Loop 18's narrow preflight adds the report boundary, candidate-range, paired
OCR, version and shortcut-icon contracts:

```powershell
.\.venv\Scripts\python.exe -m pytest `
  tests\unit\domain\daily\test_calendar.py `
  tests\unit\application\daily\test_capture.py `
  tests\unit\application\daily\test_report_workbook.py `
  tests\unit\application\daily\test_unloading_time.py `
  tests\unit\jobs\test_loop3_scheduler_policy.py `
  tests\unit\tools\test_build_formal_release.py `
  tests\unit\release\test_local_release.py `
  tests\integration\test_daily_items_api.py `
  tests\integration\test_daily_report_api.py `
  tests\integration\test_loop3_scheduler.py `
  tests\integration\test_loop4_data_foundation.py `
  tests\integration\test_loop9_platform_api.py -q
npm.cmd --prefix frontend run check
```

These commands do not replace `tools/check.py`. The capture, migration, and
projection tests use temporary databases; never exercise write acceptance
against the formal data root.

Run the offline startup preflight against a temporary data directory:

```powershell
.\.venv\Scripts\python.exe -m dahe --check --data-root .\tmp\dahe-check
```

Do not point tests at `%LOCALAPPDATA%\DaHeLogistics`. Tests must use temporary
directories supplied by pytest.

## Local read-only production release

The production entry is fixed to the operational audit and daily modules. It
cannot enable settlement, dispatch, test fixtures, or strict-shadow tools:

```powershell
$productionRoot = "$env:LOCALAPPDATA\DaHeLogistics\production"
.\.venv\Scripts\python.exe -m dahe --serve `
  --production-read-only `
  --data-root $productionRoot
```

The command binds only `127.0.0.1:8877`. If the port is occupied, it stops with
an explanation and does not select another port or terminate a process.

Build the self-contained local release only from a clean committed checkout,
after the frontend build and operational contract/template bundle exist:

```powershell
.\.venv\Scripts\python.exe tools\bootstrap_browser.py
.\.venv\Scripts\python.exe tools\build_local_production_release.py `
  --operational-source-root `
  "$env:LOCALAPPDATA\DaHeLogisticsFastCollector"
```

The release is written below
`%LOCALAPPDATA%\Programs\DaHeLogistics\releases\<version-build>`, uses its own
`.venv`, and creates the desktop shortcut `大禾物流自动化平台`. It is not an installer or
automatic updater.

Before the first production start, copy only the verified operational read
contracts and four shadow templates into the stopped production data root. The
source is read-only and no platform request is made:

```powershell
$operationalSource = "$env:LOCALAPPDATA\DaHeLogisticsFastCollector"
.\.venv\Scripts\python.exe tools\install_operational_read_contracts.py `
  --source-root $operationalSource `
  --target-root $productionRoot `
  --output "$productionRoot\operational-contract-install.json"
.\.venv\Scripts\python.exe tools\install_operational_template_bundle.py `
  --source-root $operationalSource `
  --target-root $productionRoot `
  --output "$productionRoot\operational-template-install.json"
```

Both commands are idempotent for identical content and refuse to overwrite a
different contract, template bundle, or running DaHe data root.

With the production console stopped, create and restore-check one online
backup before cutover:

```powershell
.\.venv\Scripts\python.exe tools\verify_production_backup_restore.py `
  --data-root $productionRoot `
  --output "$productionRoot\verification\production-backup-restore.json"
```

The operational acceptance command is offline and requires every real evidence
file to exist. It refuses a dirty checkout and remains the supported path for
the historical Ledger states `operational_read_only_with_guard` and
`operational_read_only_accepted`:

```powershell
.\.venv\Scripts\python.exe tools\loop9_operational_read_only_acceptance.py `
  --data-root $productionRoot `
  --release-manifest C:\absolute\release\runtime-manifest.json `
  --regression-report C:\absolute\loop7-regression.json `
  --settlement-capture-evidence C:\absolute\settlement-capture.json `
  --daily-capture-evidence C:\absolute\daily-capture.json `
  --fault-injection-evidence C:\absolute\fault-injection.json `
  --backup-restore-evidence C:\absolute\production-backup-restore.json `
  --ocr-qualification C:\absolute\ocr-qualification.json `
  --daily-report-id DAILY_REPORT_ID `
  --output C:\absolute\DaHeRepository\verification\loops\loop-9\operational\acceptance.json
```

The active read-only production policy uses
`operational_read_only_active`: machine-normal items proceed directly to the
local ready-for-settlement list while every existing business-anomaly and
technical-failure route remains fail-closed. The dedicated policy-change Ledger
writer records this transition without claiming that the strict locked-set or
shadow gates passed. The strict `shadow_accepted` workflow documented later
remains available for a future independent 50+30 validation.

## Isolated development quality tools

Install the approved, pinned development-only tools outside the project and OCR
environments:

```powershell
.\.venv\Scripts\python.exe tools\bootstrap_dev_quality.py --tool all
```

The installer uses `%LOCALAPPDATA%\DaHeLogistics\development-tools\quality`,
never the main `.venv`. It installs Gitleaks 8.30.1, pip-audit 2.10.1, py-spy
0.4.2, and Schemathesis 4.24.3. The Gitleaks Windows x64 archive is checked
against its pinned official SHA-256 before extraction. Each isolated runtime
records its resolved packages and executable hash in `runtime-installation.json`.

Run checks independently so one finding does not hide the others:

```powershell
.\.venv\Scripts\python.exe tools\run_dev_quality.py secrets
.\.venv\Scripts\python.exe tools\run_dev_quality.py dependencies
.\.venv\Scripts\python.exe tools\run_dev_quality.py api
.\.venv\Scripts\python.exe tools\run_dev_quality.py profile
```

Results are written under the same AppData quality root. The secret scan keeps
only a count and rule IDs and deletes the redacted raw report. The dependency
audit never uses `--fix`; a missing network response, an unknown package, or a
known vulnerability cannot be reported as passed. The API check starts a new
test-fixture server on a random loopback port, tests only `/meta` and
`/resources`, and cannot enable Chengfeng. The profiler can attach only to the
new offline child created by the wrapper; there is no CLI option for an
existing PID.

These checks supplement `tools/check.py`; they do not replace it and are not
production startup dependencies. Current vulnerability findings must be
reviewed before changing release or OCR locks because the scanner never updates
dependencies automatically.

## Isolated OCR quality experiment

Install the approved development-only image-quality and alternative CPU OCR
tools in separate AppData environments:

```powershell
.\.venv\Scripts\python.exe tools\bootstrap_ocr_experiment.py --tool all
```

CleanVision 0.3.7 and RapidOCR 3.9.2 are not production dependencies. Their
direct wheels are pinned by SHA-256, their resolved package inventories are
locked under `dev-tools`, and RapidOCR uses the separately pinned Microsoft
ONNX Runtime 1.28.0 Windows x64 wheel. No package is installed into the main,
browser, CPU Paddle, or GPU Paddle environment.

Run a bounded comparison only against an absolute protected Loop 7 development
record that has already been consumed for development:

```powershell
$developmentRoot = "$env:LOCALAPPDATA\DaHeLogisticsLoop7Development"
$reviewRecord = "$developmentRoot\development\protected-candidate-review-ocr\records\sha256\RECORD.json"
.\.venv\Scripts\python.exe tools\run_ocr_experiment.py `
  --development-root $developmentRoot `
  --review-record $reviewRecord `
  --sample-size 20
```

The runner verifies the record and every content-addressed image, selects a
deterministic quality-aware sample, copies inputs only into the temporary
AppData run directory, and deletes those copies after the workers finish. The
saved result contains hashes, issue types, aggregate timing, and truth-match
booleans only. It contains no OCR text, platform weight, source path, or image.
Every result is marked development-only, ineligible for a future locked set,
and prohibited from production promotion. See ADR-040.

## Formal Windows release

Download and verify the pinned NSIS 3.12 portable compiler and the official
CPython 3.12.10 64-bit embeddable archive outside the project runtime:

```powershell
.\.venv\Scripts\python.exe tools\bootstrap_windows_release_tools.py --tool all
```

The archive URLs, license sources and SHA-256 pins are checked in under
`dev-tools`. The compiler and Python archive remain under
`%LOCALAPPDATA%\DaHeLogistics\development-tools\windows-release` and are never a
production runtime dependency.

Build the five formal assets only from a clean committed checkout whose source
version matches the intended release after the authoritative checks and
frontend build pass. Keep the local archive under `dist/releases/<version>`;
the binaries are ignored by Git while `dist/README.md` documents the layout:

```powershell
$releaseOutput = Join-Path $PWD "dist\releases\1.1.4"
.\.venv\Scripts\python.exe tools\build_formal_release.py `
  --output-root $releaseOutput `
  --browser-runtime-root "$env:LOCALAPPDATA\DaHeLogistics\runtimes\browser" `
  --ocr-runtime-root "$env:LOCALAPPDATA\Programs\DaHeLogistics\ocr-runtime" `
  --gpu-runtime-root "C:\absolute\qualified\ocr-gpu" `
  --seed-root "$env:LOCALAPPDATA\DaHeLogistics\production"
```

The command builds the main application in PyInstaller one-folder mode with
UPX disabled, builds separate stable launcher and updater executables, packages
CPU OCR in the installer and GPU OCR as an optional add-on, compiles a per-user
NSIS installer, and writes exactly:

- `DaHe-Logistics-Automation-Tool-<version>-Setup.exe`
- `DaHe-Logistics-Automation-Tool-<version>-win-x64.zip`
- `DaHe-Logistics-Automation-Tool-<version>-gpu-addon-win-x64.zip`
- `update-manifest.json`
- `SHA256SUMS.txt`

Before publication, scan the setup, application, launcher and updater with the
local Microsoft Defender installation; verify the source commit, manifest,
five asset hashes, installed current pointer and readiness identity are equal.
The installer uses normal-user scope and retains product data on uninstall.
See ADR-041 and ADR-067.

For an ordinary first installation, download and run only the Setup executable.
The application ZIP is the payload used by the in-product updater. On a machine
that needs GPU OCR, also download the matching GPU add-on ZIP and the release
manifest, then let the installed versioned updater verify, qualify and activate
the add-on; do not extract it manually:

```powershell
& "$env:LOCALAPPDATA\Programs\DaHeLogisticsAutomationTool\versions\1.1.4\DaHeUpdater.exe" `
  gpu-install `
  --manifest .\update-manifest.json `
  --package .\DaHe-Logistics-Automation-Tool-1.1.4-gpu-addon-win-x64.zip `
  --install-root "$env:LOCALAPPDATA\Programs\DaHeLogisticsAutomationTool" `
  --json

& "$env:LOCALAPPDATA\Programs\DaHeLogisticsAutomationTool\versions\1.1.4\DaHeUpdater.exe" `
  gpu-status `
  --install-root "$env:LOCALAPPDATA\Programs\DaHeLogisticsAutomationTool" `
  --json
```

Activation succeeds only after NVIDIA discovery, GPU Worker hello/preflight,
two synthetic OCR fixtures and CPU/GPU critical-field parity pass on that
computer. Failure leaves the verified CPU composition unchanged.

The application ZIP carries the updater for that version. The installed
application prefers this versioned updater; the stable root updater remains as
the compatibility entry for the first upgrade from an older release. The
1.1.4 manifest accepts Schema `0039_network_batch_default` and migrates to
`0042_daily_capture_range`.

The formal CPU OCR payload uses the flat composition layout documented in
ADR-071. The build projects every archive member below a 20-character Windows
user name and rejects files over 259 characters or directories over 247
characters before NSIS is allowed to run. Development and existing 1.1.0 OCR
compositions remain readable; new installers write only the flat layout. The
formal GPU package uses the short `g` overlay layout, stores machine-bound
qualification under `gq`, and publishes `active-gpu-addon.json` only after all
checks pass. Application startup rechecks the GPU UUID, driver and memory and
falls back to CPU when that qualification is no longer current.

The three source runtime arguments must point to already qualified browser,
CPU OCR and GPU OCR environments. The builder does not publish their virtual
environments. It rebuilds each worker around the pinned embeddable Python,
keeps only isolated `Lib\site-packages`, and uses the root `python.exe` in the
formal package. The build fails if it finds `pyvenv.cfg`, `Scripts`,
`direct_url.json`, bytecode/cache files, a developer-machine absolute path, a
different worker source hash, or a runtime that cannot start. Development
runtimes may continue to use `Scripts\python.exe`; installed runtimes may not.
The formal browser runtime uses the installed Microsoft Edge and never copies
the bootstrap smoke store or any browser Profile into a release asset.

## Isolated browser runtime

Build the pinned Playwright worker in its separate per-user runtime:

```powershell
.\.venv\Scripts\python.exe tools\bootstrap_browser.py
```

The default install root is
`%LOCALAPPDATA%\DaHeLogistics\runtimes\browser`. Playwright is not installed in
the main `.venv` or either OCR environment. The bootstrap smoke runs through the
same restricted child environment used in production and does not navigate to a
network URL. It checks bundled Chromium first and then dynamically discovers the
Windows system Edge installation from whitelisted Program Files roots. A
persistent Chengfeng profile is created only under the selected DaHe data root
when an authorized human-login action starts.

Build and run the separate offline Chengfeng query twin without touching the
production browser runtime or any external host:

```powershell
$twinRuntime = "$env:LOCALAPPDATA\DaHeLogistics\development-tools\playwright-twin\1.61.0"
.\.venv\Scripts\python.exe tools\bootstrap_browser.py --runtime-root $twinRuntime
.\.venv\Scripts\python.exe tools\chengfeng_offline_twin_check.py --runtime-root $twinRuntime
```

The twin uses only a random loopback port and system Edge. It exercises atomic
response waiting, delayed responses, hidden request fields, duplicate requests,
an iframe, and blocked service workers. Its output contains only counts, timing,
fixed local paths, status, and structure hashes; it never proves that the real
Chengfeng connector is accepted.

After a current access window is established, the human-login action opens only
the code-frozen Chengfeng settlement entry and accepts only its same-origin
login redirect. Neither the local API nor the worker protocol accepts an
arbitrary URL. Discovery capture stays disabled while credentials are entered.
If the approved landing cannot be displayed, the owned browser is closed and a
specific local error is returned without consuming business data.
The worker yields human control after the approved HTTPS main response commits;
it does not wait for unrelated third-party assets or the page-wide
`DOMContentLoaded` event. The supervising deadline must remain longer than the
worker navigation deadline. The headed context disables Playwright's fixed
emulated viewport so Chengfeng follows the real Windows window size when the
window is maximized, restored, or resized.

The protected Loop 9 entry points require an explicit data root and remain
disabled during normal startup:

```powershell
.\.venv\Scripts\python.exe -m dahe --serve `
  --data-root C:\path\to\DaHeLoop9Data `
  --enable-chengfeng-shadow `
  --enable-loop9-scheduler-probe
```

Starting the server is not authorization to access Chengfeng. Before each real
window, the local API still requires fresh confirmation that the legacy program
is stopped, no collection or settlement/payment work is active, and the
same-account login risk is accepted. Do not use this option with test fixtures,
template maintenance, or locked-set review mode.

After a development-only discovery is sealed, freeze only the approved list,
detail, and response-derived ticket-image shapes into the selected DaHe data
root:

```powershell
.\.venv\Scripts\python.exe tools\loop9_freeze_read_contract.py `
  --data-root C:\absolute\DaHeLoop9Data `
  --discovery-evidence C:\absolute\DaHeLoop9Data\platform-contract-discovery\<sha256>.json
```

The command is offline, deterministic, and idempotent. It rejects evidence
outside the selected data root, tampered content-addressed files, missing
required response fields, and captures without signed ticket-image shapes. The
real contract remains in AppData; the checked-in contract fixture is
non-routable. A frozen candidate is not a passed real-request gate until a
separately authorized live read validates it.

Select one frozen candidate explicitly before the live validation service can
use it:

```powershell
.\.venv\Scripts\python.exe tools\loop9_select_read_contract.py `
  --data-root C:\absolute\DaHeLoop9Data `
  --contract-canonical-sha256 <canonical-sha256> `
  --contract-file-sha256 <file-sha256> `
  --freeze-evidence-sha256 <freeze-evidence-sha256>
```

Selection is offline, immutable, and idempotent. It verifies the content
addressed contract and freeze evidence, but it does not pass the real-request
gate. Formal reads use browser worker protocol version 3. After human control
is returned, the worker closes the Chengfeng page, keeps an aborted
`about:blank` page, and performs only typed list, detail, or response-derived
image reads. Redirects are disabled. Raw responses are staged in the selected
DaHe data root, rehashed by the main process, normalized into the existing
connector boundary, and removed immediately. Complete signed image URLs remain
in memory behind five-minute opaque capabilities and are never written to logs
or evidence.

To keep the fast business collector separate from Loop 9 formal evidence,
install only the currently selected settlement and daily contract dependency
closures into the stopped operational data root:

```powershell
.\.venv\Scripts\python.exe tools\install_operational_read_contracts.py `
  --source-root "$env:LOCALAPPDATA\DaHeLogisticsLoop9Discovery20260729" `
  --target-root "$env:LOCALAPPDATA\DaHeLogisticsFastCollector" `
  --output "$env:LOCALAPPDATA\DaHeLogisticsFastCollector\operational-contract-install.json"
```

The target DaHe instance must be stopped. The installer rejects links,
reparse points, missing or changed dependencies, and different existing target
content. It never copies databases, images, browser profiles, credentials, or
formal samples. Its deterministic evidence is classified `operational_only`
and cannot satisfy a Loop 9 formal Gate. After restarting the operational
console, clicking a business page's acquire button authorizes only that one
read-only Job; strict validation still uses its separate access-window flow.

If the official reset request changes shape, create a development rollover
candidate from the value-free structure diagnostic. This is a recovery branch,
not a formal Gate:

```powershell
.\.venv\Scripts\python.exe tools\loop9_rollover_list_contract.py `
  --data-root C:\absolute\DaHeLoop9Data `
  --request-structure-evidence C:\absolute\DaHeLoop9Data\platform-contract-discovery\REQUEST_STRUCTURE_EVIDENCE.json
```

Select the emitted candidate with `loop9_select_read_contract.py` and repeat
the live read validation. A rollover never inherits a passed Gate.

The Chengfeng detail endpoint is form encoded even though the selected list
endpoint is JSON encoded. Historical discovery evidence that recorded the
detail request as JSON remains replayable, but live reads reject it. Create and
select the content-preserving encoding rollover before live validation:

```powershell
.\.venv\Scripts\python.exe tools\loop9_rollover_detail_encoding_contract.py `
  --data-root C:\absolute\DaHeLoop9Data
```

The command changes only the detail request location from `json` to `form`,
deeply revalidates the inherited list, response, detail, and image contracts,
and records the parent hashes. Any semantic contract change fails closed.

The loading/unloading backend uses a separately frozen daily-list contract.
Create each validation job with `scope=last_completed`; the server freezes one
`daily:YYYY-MM-DD` work item and never derives the target date again at capture
time. The browser preflight and every formal list request use the same bounded
page size of five so the first response can be reused exactly rather than
discarded and reread under different pagination. Each snapshot reads every list
page twice and commits only when both passes have the same count, pagination
metadata, and waybill identity set.
Formal daily validation requires three independently completed snapshots of
that same scope, produced under three distinct access windows. The validator
reopens the active selected daily contract evidence and hashes its complete
selection chain into the result. Formal creation and replay fail closed unless
the forbidden-request, platform-write, and redirect counters are all zero:

```powershell
.\.venv\Scripts\python.exe tools\loop9_validate_daily_snapshots.py `
  --data-root C:\absolute\DaHeLoop9Data `
  --snapshot-id <first-job-id> `
  --snapshot-id <second-job-id> `
  --snapshot-id <third-job-id> `
  --output C:\absolute\DaHeLoop9Data\verification\daily-triplet.json
```

The 50-waybill locked set, 30-waybill real shadow set, development discovery,
daily validation, and historical exclusions must then be supplied to the
dataset-isolation gate. Build the normalized manifests from their sealed source
artifacts; do not hand-author formal dataset JSON:

```powershell
.\.venv\Scripts\python.exe tools\loop9_build_dataset_artifacts.py discovery `
  --validation-evidence C:\absolute\evidence\live-validation.json `
  --development-inventory C:\absolute\DaHeLoop9Data\loop9-development-exclusions\INVENTORY_SHA256.json `
  --dataset-id loop9-discovery-development `
  --output C:\absolute\evidence\discovery.json

.\.venv\Scripts\python.exe tools\loop9_build_dataset_artifacts.py formal `
  --data-root C:\absolute\DaHeLoop9Data `
  --shadow-batch C:\absolute\DaHeLoop9Data\chengfeng-shadow-batches\LOCKED_MANIFEST_SHA256.json `
  --formal-selection C:\absolute\DaHeLoop9Data\loop9-formal-selections\LOCKED_SELECTION_SHA256.json `
  --dataset-id loop9-current-locked-50 `
  --output C:\absolute\evidence\locked-50.json

.\.venv\Scripts\python.exe tools\loop9_build_dataset_artifacts.py formal `
  --data-root C:\absolute\DaHeLoop9Data `
  --shadow-batch C:\absolute\DaHeLoop9Data\chengfeng-shadow-batches\SHADOW_MANIFEST_SHA256.json `
  --formal-selection C:\absolute\DaHeLoop9Data\loop9-formal-selections\SHADOW_SELECTION_SHA256.json `
  --dataset-id loop9-real-shadow-30 `
  --output C:\absolute\evidence\shadow-30.json

.\.venv\Scripts\python.exe tools\loop9_build_dataset_artifacts.py daily-inventory `
  --data-root C:\absolute\DaHeLoop9Data `
  --daily-validation C:\absolute\DaHeLoop9Data\verification\daily-triplet.json `
  --output C:\absolute\DaHeLoop9Data\verification\daily-inventory.json

.\.venv\Scripts\python.exe tools\loop9_build_dataset_artifacts.py daily-manifest `
  --data-root C:\absolute\DaHeLoop9Data `
  --daily-validation C:\absolute\DaHeLoop9Data\verification\daily-triplet.json `
  --dataset-id loop9-daily-validation `
  --output C:\absolute\DaHeLoop9Data\verification\daily-dataset.json
```

DaHe creates and reuses one installation-local identity authority inside the
active data root. Discovery, locked-set, shadow, and daily artifacts must all
bind to that same irreversible identity context. The tool never writes the
key, its path, or the namespace into formal evidence.
The `daily-manifest` command never accepts an external inventory as authority.
It reloads the selected daily contract, all three SQLite snapshot authorities
and observations, their sealed request audits, the existing identity authority,
and every content-addressed image from the formal data root before rebuilding
the inventory and manifest. Current formal evidence requires schema v5; schema
v4 remains historical read-only evidence.
The locked set, shadow set, and daily triplet must resolve to the same
irreversible identity-context SHA-256. A daily snapshot with no locally verified
ticket image fails closed; the tool never fabricates image participation.

Before any formal selection is used, convert the sealed Loop 7 source
authority into one installation-bound inventory, then advance the
installation-local full-history exclusion authority. The conversion reads the
existing identity authority without creating or exposing it, preserves every
source image, perceptual fingerprint, and irreversible waybill identity, and
fails before writing if the source boundary is incomplete. Discovery platform
identities must first be piped through standard input so they never appear in
a command line:

```powershell
$platformIdentities | & .\.venv\Scripts\python.exe tools\loop9_register_discovery_exclusion.py `
  --data-root C:\absolute\DaHeLoop9Data `
  --discovery-evidence C:\absolute\DaHeLoop9Data\platform-contract-discovery\DISCOVERY_SHA256.json

.\.venv\Scripts\python.exe tools\loop9_build_dataset_artifacts.py legacy-loop7-exclusions `
  --data-root C:\absolute\DaHeLoop9Data `
  --source-development-authority C:\absolute\formal-development-authorities\SOURCE_AUTHORITY_SHA256.json `
  --inventory-id loop9-legacy-loop7-source `
  --output C:\absolute\DaHeLoop9Data\verification\loop7-exclusions.json

.\.venv\Scripts\python.exe tools\loop9_build_exclusion_authority.py `
  --data-root C:\absolute\DaHeLoop9Data `
  --source-development-authority C:\absolute\formal-development-authorities\SOURCE_AUTHORITY_SHA256.json `
  --child-inventory C:\absolute\evidence\loop7-exclusions.json `
  --output C:\absolute\evidence\full-history-exclusion-authority.json
```

The development registry under the selected data root is included
automatically. `--source-development-authority` is always the exact formal
development-authority file, not the audit copy written by
`loop9_build_exclusion_authority.py`.

Run the full dataset-isolation gate only after both the 50-item locked set and
the 30-item shadow set have been selected, reviewed, and sealed:

```powershell
.\.venv\Scripts\python.exe tools\loop9_validate_dataset_isolation.py `
  --data-root C:\absolute\DaHeLoop9Data `
  --discovery-development C:\absolute\evidence\discovery.json `
  --current-locked-50 C:\absolute\evidence\locked-50.json `
  --real-shadow-30 C:\absolute\evidence\shadow-30.json `
  --daily-validation C:\absolute\evidence\daily.json `
  --source-development-authority C:\absolute\formal-development-authorities\SOURCE_AUTHORITY_SHA256.json `
  --output C:\absolute\evidence\dataset-isolation.json
```

Replay the persisted result from all immutable inputs before using it as
gate evidence:

```powershell
.\.venv\Scripts\python.exe tools\loop9_replay_dataset_isolation.py `
  --data-root C:\absolute\DaHeLoop9Data `
  --discovery-development C:\absolute\evidence\discovery.json `
  --current-locked-50 C:\absolute\evidence\locked-50.json `
  --real-shadow-30 C:\absolute\evidence\shadow-30.json `
  --daily-validation C:\absolute\evidence\daily.json `
  --source-development-authority C:\absolute\formal-development-authorities\SOURCE_AUTHORITY_SHA256.json `
  --evidence C:\absolute\evidence\dataset-isolation.json
```

Create the 50-item locked-set visual draft only from the exact active formal
selection and its content-addressed source batch. `init` deliberately leaves
every role unknown, every weight empty, every quality list empty, and every
pair unknown. Fill those fields by looking at the original images, then run
`seal`; sealing requires one explicit rotation condition per image and never
uses the upload slot, platform weight, OCR result, or machine result as truth:

```powershell
.\.venv\Scripts\python.exe tools\loop9_draft_suggestions.py init `
  --data-root C:\absolute\DaHeLoop9Data `
  --formal-selection C:\absolute\DaHeLoop9Data\loop9-formal-selections\SELECTION_SHA256.json `
  --source-batch C:\absolute\DaHeLoop9Data\chengfeng-shadow-batches\BATCH_SHA256.json `
  --output C:\absolute\evidence\locked-50-visual-draft.json

.\.venv\Scripts\python.exe tools\loop9_draft_suggestions.py seal `
  --data-root C:\absolute\DaHeLoop9Data `
  --formal-selection C:\absolute\DaHeLoop9Data\loop9-formal-selections\SELECTION_SHA256.json `
  --source-batch C:\absolute\DaHeLoop9Data\chengfeng-shadow-batches\BATCH_SHA256.json `
  --draft C:\absolute\evidence\locked-50-visual-draft.json `
  --output C:\absolute\evidence\locked-50-suggestions.json
```

The sealed suggestions remain `unconfirmed_non_truth`; only the later
item-by-item human confirmation becomes truth. Prepare the immutable 50-item
package with the independent suggestions. Review mode is offline-only and
cannot be combined with Chengfeng, OCR, template, fixture, or legacy locked-set
modes:

```powershell
.\.venv\Scripts\python.exe tools\loop9_human_review.py prepare `
  --data-root C:\absolute\DaHeLoop9Data `
  --source-batch C:\absolute\DaHeLoop9Data\chengfeng-shadow-batches\LOCKED_BATCH_SHA256.json `
  --dataset-manifest C:\absolute\evidence\locked-50.json `
  --formal-selection C:\absolute\DaHeLoop9Data\loop9-formal-selections\LOCKED_SELECTION_SHA256.json `
  --image-root C:\absolute\DaHeLoop9Data\evidence `
  --auxiliary C:\absolute\evidence\locked-50-suggestions.json `
  --output-dir C:\absolute\evidence\locked-50-review-package

.\.venv\Scripts\python.exe -m dahe --serve `
  --data-root C:\absolute\DaHeLoop9ReviewData `
  --loop9-review-package C:\absolute\evidence\locked-50-review-package
```

The console saves identity-free drafts on the server, requires both original
image hashes to be explicitly checked before each confirmation, and writes the
completed canonical answer file under
`<data-root>\review-exports`. Seal the completed answers:

```powershell
.\.venv\Scripts\python.exe tools\loop9_human_review.py seal `
  --data-root C:\absolute\DaHeLoop9Data `
  --package-dir C:\absolute\evidence\locked-50-review-package `
  --review-answers C:\absolute\DaHeLoop9ReviewData\review-exports\loop9-human-review-answers-SHA256.json `
  --output C:\absolute\evidence\locked-50-human-review-seal.json
```

The formal audit Job referenced below must come from this exact
`current_locked_50` selection and must be terminal with all OCR observations
committed. It is not the settlement-capture Job. Stop the main DaHe console
before running the command because the CLI takes the same data-root
single-instance lock:

```powershell
.\.venv\Scripts\python.exe tools\loop9_machine_results.py run `
  --data-root C:\absolute\DaHeLoop9Data `
  --source-batch C:\absolute\DaHeLoop9Data\chengfeng-shadow-batches\LOCKED_BATCH_SHA256.json `
  --source-selection C:\absolute\DaHeLoop9Data\loop9-formal-selections\LOCKED_SELECTION_SHA256.json `
  --job-id LOCKED_AUDIT_JOB_ID `
  --package-dir C:\absolute\evidence\locked-50-review-package `
  --seal C:\absolute\evidence\locked-50-human-review-seal.json

.\.venv\Scripts\python.exe tools\loop9_machine_results.py evaluate `
  --data-root C:\absolute\DaHeLoop9Data `
  --package-dir C:\absolute\evidence\locked-50-review-package `
  --seal C:\absolute\evidence\locked-50-human-review-seal.json `
  --machine-result LOCKED_MACHINE_RESULT_PATH_FROM_RUN `
  --locked-selection C:\absolute\DaHeLoop9Data\loop9-formal-selections\LOCKED_SELECTION_SHA256.json
```

`run` has no output-path option; retain the emitted `machine_result`,
`canonical_sha256`, and failure counts. The 30-item selection cannot be created
unless `evaluate` returns `gate_passed=true` and a non-empty
`current_locked_gate_sha256`.

After the 30-item selection and its formal audit Job are complete, first build
the machine result without human inputs. This produces two different files:
`machine_result` is retained for final evaluation, while
`shadow_review_auxiliary` is the only machine file supplied to the review UI:

```powershell
.\.venv\Scripts\python.exe tools\loop9_machine_results.py run `
  --data-root C:\absolute\DaHeLoop9Data `
  --source-batch C:\absolute\DaHeLoop9Data\chengfeng-shadow-batches\SHADOW_BATCH_SHA256.json `
  --source-selection C:\absolute\DaHeLoop9Data\loop9-formal-selections\SHADOW_SELECTION_SHA256.json `
  --job-id SHADOW_AUDIT_JOB_ID

.\.venv\Scripts\python.exe tools\loop9_human_review.py prepare `
  --data-root C:\absolute\DaHeLoop9Data `
  --source-batch C:\absolute\DaHeLoop9Data\chengfeng-shadow-batches\SHADOW_BATCH_SHA256.json `
  --dataset-manifest C:\absolute\evidence\shadow-30.json `
  --formal-selection C:\absolute\DaHeLoop9Data\loop9-formal-selections\SHADOW_SELECTION_SHA256.json `
  --image-root C:\absolute\DaHeLoop9Data\evidence `
  --auxiliary SHADOW_REVIEW_AUXILIARY_PATH_FROM_RUN `
  --output-dir C:\absolute\evidence\shadow-30-review-package

.\.venv\Scripts\python.exe -m dahe --serve `
  --data-root C:\absolute\DaHeLoop9ShadowReviewData `
  --loop9-review-package C:\absolute\evidence\shadow-30-review-package

.\.venv\Scripts\python.exe tools\loop9_human_review.py seal `
  --data-root C:\absolute\DaHeLoop9Data `
  --package-dir C:\absolute\evidence\shadow-30-review-package `
  --review-answers C:\absolute\DaHeLoop9ShadowReviewData\review-exports\loop9-human-review-answers-SHA256.json `
  --output C:\absolute\evidence\shadow-30-human-review-seal.json
```

Only after both packages and the full dataset-isolation evidence exist, replay
each human seal and evaluate the 30-item machine result:

```powershell
.\.venv\Scripts\python.exe tools\loop9_human_review.py replay `
  --data-root C:\absolute\DaHeLoop9Data `
  --package-dir C:\absolute\evidence\locked-50-review-package `
  --seal C:\absolute\evidence\locked-50-human-review-seal.json `
  --isolation-evidence C:\absolute\evidence\dataset-isolation.json `
  --output C:\absolute\evidence\locked-50-human-review-replay.json

.\.venv\Scripts\python.exe tools\loop9_human_review.py replay `
  --data-root C:\absolute\DaHeLoop9Data `
  --package-dir C:\absolute\evidence\shadow-30-review-package `
  --seal C:\absolute\evidence\shadow-30-human-review-seal.json `
  --isolation-evidence C:\absolute\evidence\dataset-isolation.json `
  --output C:\absolute\evidence\shadow-30-human-review-replay.json

.\.venv\Scripts\python.exe tools\loop9_machine_results.py evaluate `
  --data-root C:\absolute\DaHeLoop9Data `
  --package-dir C:\absolute\evidence\shadow-30-review-package `
  --seal C:\absolute\evidence\shadow-30-human-review-seal.json `
  --machine-result SHADOW_MACHINE_RESULT_PATH_FROM_RUN
```

The 30-item evaluation must not receive `--locked-selection`.

If all 50 waybills were reviewed but the natural images do not cover every
required quality condition, stop before sealing or machine evaluation. Retire
that exact generation and register all 50 waybills and 100 images as
development exclusions with the current build SHA-256 recorded by its source
batch:

```powershell
.\.venv\Scripts\python.exe tools\loop9_invalidate_locked_selection.py `
  --data-root C:\absolute\DaHeLoop9Data `
  --selection-sha256 LOCKED_SELECTION_SHA256 `
  --review-package C:\absolute\evidence\human-review-package `
  --review-answers C:\absolute\DaHeLoop9ReviewData\review-exports\loop9-human-review-answers-SHA256.json `
  --expected-current-build-sha256 CURRENT_BUILD_SHA256 `
  --output C:\absolute\evidence\locked-selection-invalidation.json
```

The command is offline, content-addressed, atomic, and safe to retry with the
same inputs. It rejects incomplete reviews, complete coverage, build or
contract drift, symbolic links, a different active generation, and any attempt
to reuse an older invalidated generation after its replacement is active.

Both isolation commands derive the current build fingerprint and the active
settlement and daily contract selections from the project and the supplied
data root; callers cannot substitute authority SHA-256 values. The tool rejects
exact platform-identity overlap, image-hash overlap,
perceptual near-overlap, missing formal image fingerprints,
classification/count errors, identity-context drift, build or contract drift,
and evidence tampering. The 30-waybill shadow set must contain exactly 60 unique
images. None of these build, validation, or replay commands connects to
Chengfeng.

## Isolated OCR runtimes

For a CPU-only computer, build the portable runtime and explicitly provision
the approved local open-source models:

```powershell
tools\bootstrap_ocr.cmd cpu --provision-models --model-source aistudio
```

On a machine with a compatible NVIDIA device, build and qualify CPU, GPU, and
models as one composition. The selected GPU profile is part of the published
qualification:

```powershell
tools\bootstrap_ocr.cmd all --provision-models --model-source aistudio `
  --precision fp16 --batch-size 6
```

When an active verified model set already exists, omit `--provision-models`;
the bootstrap copies and re-verifies it inside the new candidate generation.

The main `.venv`, CPU OCR, and GPU OCR use separate dependency locks. The
bootstrap never installs Paddle into the main application environment and
never combines the CPU and GPU distributions in one environment. Each OCR
runtime is built from scratch in a staging directory, checked against its full
package inventory, and smoke-tested before it atomically replaces the previous
runtime. CPU, GPU, models, and qualification are sealed in a versioned
generation. A single `active-composition.json` pointer is replaced only after
the whole generation passes smoke, so a failed candidate leaves the previous
composition available. GPU-only activation is rejected because it could
silently pair a new GPU runtime with stale CPU fallback evidence.

Paddle's Windows inference layer cannot safely load this model set from every
Unicode path. The bootstrap uses `.runtime` when the repository path is ASCII;
otherwise it selects an ASCII per-user application install path. Deployment
can override that choice without editing source:

```powershell
tools\bootstrap_ocr.cmd all --runtime-root D:\DaHeOcr
```

The selected root must be an absolute ASCII path and must not be a drive root.
The current GPU index is discovered at startup and is never persisted as the
device identity. An administrator may select a stable GPU UUID or use automatic
selection.

To recheck the active composition without changing the published profile, run
the synthetic smoke and CPU/GPU critical-field comparison:

```powershell
.\.venv\Scripts\python.exe tools\ocr_runtime_check.py all `
  --precision fp16 `
  --batch-size 6
```

The smoke uses two generated non-business images representing loading and
unloading tickets. It proves installation, strict protocol handling, Unicode
evidence paths, exact local model loading, hash correlation, role observation,
and CPU/GPU critical-field parity for those two synthetic images. It also
records per-runtime P50/P95 timings and the GPU memory peak, but the sample is
too small to be an OCR accuracy or throughput benchmark. Standard console
startup verifies and composes the qualified local OCR runtime, while every
current audit fixture remains explicitly marked as fake and never reaches that
worker protocol. Real ticket processing is connected only in the later offline
audit loop.

## Ticket templates and role development

The Loop 7 material below documents and replays evidence sealed before
ADR-019. Identity-bearing generation and publication commands in this section
are historical only and must not be used to create new templates, evaluations,
authorities, challenges, or locked-set evidence. New active records use the
identity-free contracts described in the Loop 8 section. Existing sealed files
remain byte-for-byte unchanged so their hashes can still be verified.

Template maintenance is disabled during normal console startup. Use an explicit
isolated data root to open the developer workbench:

```powershell
.\.venv\Scripts\python.exe -m dahe --serve `
  --data-root .\.tmp\loop7-template-studio `
  --enable-template-studio
```

The terminal prints a one-run maintenance access code. The browser stores only
a short-lived, HTTP-only maintenance session; the code is not written to the
database. Publishing or rolling back a shadow version requires another
action-specific revalidation. Ordinary finance sessions can view template
status but cannot change templates.

Templates use immutable versions and content-addressed reference-image holds.
The supported lifecycle is `draft -> development_tested -> shadow`; there is no
Loop 7 API or UI path to publish an `active` template. An empty workbench starts
with the same protected `Add ticket template` flow used for later families:
upload a PNG or JPEG reference, choose its role, mark at least one stable anchor,
and create the first immutable draft. The server verifies the image, applies its
EXIF orientation, rewrites it as a deterministic metadata-free PNG, stages it
under a content-addressed identity, and derives the anchor mask itself. The
browser never supplies a trusted image hash or mask file.

A completed candidate-review OCR record may also seed one development draft,
but only through the protected local command below. Stop every console that
uses the target data root first. The definition file must use the exact
canonical template-definition JSON contract, and its role must match both
`--expected-role` and the direct human review:

The OCR record must come from
`tools\loop7_candidate_development_evaluation.py` on the same data root. A
successful run now appends a SQLite authority that binds the logical evidence
identity to the exact JSON bytes and protected path, human-review authorities,
application build, qualified CPU/GPU runtime set, pipeline contract, and
completion time. A copied, manually rewritten, or older record without that
authority cannot seed a template.

```powershell
.\.venv\Scripts\python.exe tools\loop7_candidate_template_seed.py `
  --data-root C:\path\to\DaHeDevelopmentData `
  --evidence C:\path\to\DaHeDevelopmentData\development\protected-candidate-review-ocr\records\sha256\AA\BB\EVIDENCE_SHA256.json `
  --evidence-sha256 EVIDENCE_SHA256 `
  --sample-id L7-002 `
  --submitted-slot loading `
  --expected-role loading `
  --definition C:\isolated\loading-template-definition.json `
  --actor-id developer-name `
  --idempotency-key loading-template-v1
```

The command rehashes the protected record and all 100 copied images, reconciles
the 50 human-reviewed waybills, requires successful CPU and GPU evidence, and
rejects an unknown role, non-ticket, unknown layout, or role mismatch. It
normalizes the selected image and derives the mask on the server side. The
draft, immutable source provenance, original-image hold, development-image
exclusion, and source-waybill exclusion commit together. Its terminal result
contains only template and provenance identities, not OCR text or weights.

A lifecycle transition must name the absolute latest completed composite
development evaluation for that candidate. Its real-image component must load
the protected OCR record through the same append-only SQLite run authority used
by template seeding; a self-hashed JSON file alone is not lifecycle evidence.
Its synthetic component must come from the code-owned frozen runner, and the
parent record must still match the accepted fixture manifest, matcher policy,
application build, qualified OCR runtime set, complete template set, stable
pair outcomes, item count, metric hash, and per-image records in SQLite. An
invalid or invalidated newer record never revives older evidence. Invalidating
an evaluation also withdraws any current shadow pointer it authorized.

Run the frozen synthetic development evaluation without starting the console:

```powershell
.\.venv\Scripts\python.exe tools\loop7_development_evaluation.py `
  --output .\.tmp\loop7-development-evaluation.json
```

This exercises fixed text, template geometry, all four orientations, safe
`unknown` results, and the existing two-ticket role contract. It contains no
production images and cannot establish real ticket accuracy. Field reliability
is reported as not measured because this Loop 7 runner does not execute field
extraction.

To persist a development evaluation against an isolated local data root, stop
the console first and run:

```powershell
.\.venv\Scripts\python.exe tools\loop7_development_evaluation.py `
  --output .\.tmp\loop7-persisted-evaluation.json `
  --persist `
  --data-root C:\path\to\DaHeData `
  --candidate-version VERSION_ID_1 `
  --candidate-version VERSION_ID_2
```

The command takes the normal single-instance lock, qualifies the installed OCR
runtime, reloads candidate versions from SQLite, and uses only the
version-controlled development dataset whose canonical SHA-256 is fixed in the
code-owned registry. An external path, copied dataset, changed dataset, caller
report, or generated regression fixture cannot authorize lifecycle changes.
The command atomically activates the accepted development contract for later
console restarts and makes no Chengfeng or other network request.

The approved development dataset contains 19 explicit code-authored synthetic
OCR observations covering all four formal seed anchors, both roles at four
orientations, unknown layout, non-ticket, mixed-conflict, normal-pair, and
swapped-pair behavior. Every role-positive observation also includes the
independent ticket markers `磅单` and `净重`; a role anchor alone never grants
ticket eligibility. It can
authorize only the development and shadow lifecycle; it is not a real image
dataset, has no human labels, and cannot establish ticket accuracy.

Candidate selection and human labeling use a separate offline review mode.
First stop the development console and export the current development
authority to a new file outside every application data root:

```powershell
.\.venv\Scripts\python.exe tools\loop7_locked_set_release.py `
  export-development-authority `
  --data-root C:\path\to\DaHeDevelopmentData `
  --output C:\isolated\loop7-development-authority.json
```

The export revalidates the approved development manifest, current eligible
shadow templates, their accepted evaluations and lifecycle attempts, and the
complete development exclusion inventory. Record the printed
`authority_sha256`. The authority file is an immutable handoff, not an
independent source of trust: formal preparation and evaluation later reopen
and revalidate the same development data root.

Use that exact file for discovery. Existing optional `--result-root` and
exclusion inputs may still be supplied, but they can only narrow identities
already present in the development authority:

```powershell
.\.venv\Scripts\python.exe tools\loop7_legacy_candidate_review.py discover `
  --legacy-data-root C:\path\to\LegacyData `
  --acquisition-root C:\path\to\LegacyAcquisition `
  --development-authority C:\isolated\loop7-development-authority.json `
  --output C:\isolated\loop7-discovery.json
```

Do not hand-author the bound selection JSON after `discover`. Put exactly 50
candidate IDs into a UTF-8 text file, one ID per non-empty line, then freeze
them against the unchanged discovery snapshot:

```powershell
.\.venv\Scripts\python.exe tools\loop7_legacy_candidate_review.py `
  create-selection `
  --legacy-data-root C:\path\to\LegacyData `
  --discovery C:\isolated\loop7-discovery.json `
  --candidate-ids-file C:\isolated\candidate-ids.txt `
  --output C:\isolated\loop7-selection.json
```

`create-selection` accepts only 50 unique IDs present in that discovery and
writes the exact candidate-index, source-manifest, exclusion-snapshot, and
development-authority hashes required by `contact-sheets` and `stage`. Re-run
`discover` if any source, exclusion, or development authority changes; never
copy hashes between discovery runs. Run `contact-sheets` with the same source
arguments when visual selection aids are needed, then stage the review package
with the same authority:

```powershell
.\.venv\Scripts\python.exe tools\loop7_legacy_candidate_review.py stage `
  --legacy-data-root C:\path\to\LegacyData `
  --acquisition-root C:\path\to\LegacyAcquisition `
  --development-authority C:\isolated\loop7-development-authority.json `
  --selection C:\isolated\loop7-selection.json `
  --output-root C:\path\to\DaHeLockedSetReviewData\locked-set-review `
  --package-id LOOP7_CANDIDATE_PACKAGE_ID
```

The review data root must then contain a sealed `locked-set-review` package with
exactly 50 waybills and 100 unique images:

```powershell
.\.venv\Scripts\python.exe -m dahe --serve `
  --data-root C:\path\to\DaHeLockedSetReviewData `
  --enable-locked-set-review
```

Review mode runs by itself: it cannot be combined with template tuning, test
fixtures, OCR, or Chengfeng access. The console opens in the system default
browser. Open **System**, then **Development & Maintenance**, then
**Locked-set review**. Candidate clues are discovery aids only, never
preselected truth. Reviewers must decide from the two original images and may
mark an unsuitable sample for replacement instead of forcing a label. Saved
records remain local, append-only, versioned, and contain no human identity.
Completing all 50 records does
not release the locked set; a later fail-closed export and the formal validation
workflow below are still required.

The existing Loop 7 seal is historical evidence. It must not be regenerated
through the pre-ADR-019 identity-bearing export path. Its source is
`C:\path\to\DaHeLockedSetReviewData\locked-set-review`; do not copy or edit the
files under `seals\<seal_sha256>`. The seal requires exactly 50 independently
reviewed waybills and 100 unique images. Loading and unloading upload slots
remain separate from the human-confirmed ticket roles. An unknown layout uses
role `unknown` and has no ordinary-net truth. A non-ticket image is evaluated
by the separate controlled challenge below and is not inserted into the
natural locked set.

After all formal-pipeline source changes are final, roll the four current
shadow templates forward without changing their definitions or reference
evidence. The command is idempotent, requires qualified CPU and GPU runtimes,
and leaves every prior template version immutable:

```powershell
.\.venv\Scripts\python.exe tools\loop7_shadow_authority_rollover.py `
  --data-root C:\path\to\DaHeDevelopmentData `
  --ocr-evidence C:\path\to\protected-ocr-record.json `
  --output C:\isolated\loop7-shadow-authority-rollover.json
```

Keep the printed source authority, execution authority, and rollover SHA-256.
The source authority remains responsible for how the 50 reviewed samples were
selected. The execution authority binds the final code and replacement shadow
versions. The rollover evidence proves that every replacement is a direct,
same-content revision with the same reference image, mask, alignment,
development inventory, matcher, policy, dataset, and qualified runtime set.

Prepare the formal review only from that seal. Stop every console using either
the development or formal data root. The formal data root must be new and
independent; do not copy a development database, template table, browser
profile, or evidence directory into it. Use a new output path outside all three
data roots:

```powershell
.\.venv\Scripts\python.exe tools\loop7_locked_set_release.py prepare-candidate `
  --data-root C:\path\to\DaHeLockedSetFormalData `
  --candidate-review-root C:\path\to\DaHeLockedSetReviewData\locked-set-review `
  --development-data-root C:\path\to\DaHeDevelopmentData `
  --development-authority-sha256 DEVELOPMENT_AUTHORITY_SHA256 `
  --source-development-authority-sha256 SOURCE_DEVELOPMENT_AUTHORITY_SHA256 `
  --development-authority-rollover C:\isolated\loop7-shadow-authority-rollover.json `
  --seal-sha256 SEAL_SHA256 `
  --review-output C:\isolated\loop7-review-prepared.json
```

`prepare-candidate` locks both application data roots in deterministic path
order, rebuilds the execution authority from the live development root, and
requires the explicit rollover chain to lead back to the source authority
sealed into the candidate review. It imports only the verified exclusion
identities and fingerprints into the fresh formal root, binds all three
authority SHA-256 values to the formal dataset, revalidates the immutable
review seal, stages the 100 images, and scans exact and perceptual reuse. It
remains offline and does not start OCR. The sealed
`quality_coverage.entries` and `derived_adversarial_suite` are read-only;
`bind-review` may not recalculate or replace them. The sealed identity-bearing
schema is accepted only by the read-only legacy verifier and must never be
copied into a new business or verification record.

The sealed human quality evidence contains exactly 10 image-bound conditions:
`blur`, `crop`, `glare`, `printed`, `rotation_0`, `rotation_90`,
`rotation_180`, `rotation_270`, `screen`, and `unknown_layout`. The four
rotation conditions require four distinct images; printed and screen evidence
must be distinct; unknown-layout evidence must have human truth `unknown` and
no ordinary-net truth. There are no human pair-quality entries for swapped,
same-role, or duplicate pairs.

Create the separate non-ticket challenge from one previously unseen local
image. The original is read only long enough to produce a metadata-free,
irreversibly redacted PNG. Only the redacted artifact is stored under the
configured challenge AppData root:

```powershell
.\.venv\Scripts\python.exe tools\loop7_controlled_non_ticket_challenge.py create `
  --source-image C:\path\to\unseen-non-ticket.png `
  --output-root C:\path\to\DaHeChallengeData `
  --development-authority C:\path\to\sealed\development-authority.json `
  --package-data-root C:\path\to\DaHeLockedSetReviewData `
  --created-at 2026-07-27T23:00:00+08:00 `
  --redact 35,110,895,535 `
  --redact 420,570,920,734
```

After formal preparation, evaluate that artifact through the same final
shadow templates and qualified CPU/GPU composition:

```powershell
.\.venv\Scripts\python.exe tools\loop7_controlled_non_ticket_challenge.py evaluate `
  --manifest C:\path\to\challenge\manifest.json `
  --development-authority C:\path\to\sealed\development-authority.json `
  --package-data-root C:\path\to\DaHeLockedSetReviewData `
  --development-data-root C:\path\to\DaHeDevelopmentData `
  --formal-data-root C:\path\to\DaHeLockedSetFormalData `
  --development-authority-rollover C:\isolated\loop7-shadow-authority-rollover.json
```

Both runtimes must return `unknown`, an unreliable ordinary net, and the
`non_automatic` safety route. Putting the challenge into either upload slot
must produce `awaiting_review` with `role_unknown`. Its result is stored
separately and is excluded from the natural sample count, confusion matrix,
accuracy, unknown rate, latency, layout distribution, and prevalence claims.

## Loop 8 offline audit batch

Prepare the 12-item acceptance batch only from DaHe development evidence. The
output root is independent from the legacy program and contains anonymous IDs,
content-addressed images, and no human identity:

```powershell
.\.venv\Scripts\python.exe tools\loop8_prepare_offline_batch.py `
  --formal-report C:\path\to\loop7-formal-report.json `
  --source-image-root C:\path\to\DaHeLockedSetReviewData\locked-set-review\images `
  --output-data-root C:\path\to\DaHeLogisticsLoop8Offline
```

Start the application with that output as `--data-root`. The normal audit start
button automatically selects `offline-audit\loop8-offline-v1.json`, while a
data root without that manifest keeps the earlier single-item development
fixture. The batch is offline and cannot issue Chengfeng requests.

The formal workflow deterministically generates a separate relationship
anomaly suite from the already confirmed real-image roles. A manifest- and
generator-version-bound rule swaps the slots of one normal pair, combines two
distinct confirmed loading images, combines two distinct confirmed unloading
images, and binds one exact image hash to both slots. The required results are:

- `swapped_slots`: `awaiting_review` with `suspected_swapped`
- `both_loading`: `awaiting_review` with `both_loading`
- `both_unloading`: `awaiting_review` with `both_unloading`
- `exact_duplicate_image`: `awaiting_review` with `duplicate_image`

These four cases do not add to or replace the 50 real waybills or 100 unique
real images. They are excluded from real-sample counts, confusion matrices,
accuracy, unknown rate, latency, and occurrence-rate claims. In particular,
`exact_duplicate_image` proves only the identical-content-hash case; it does
not claim detection of two different hashes that depict the same ticket.
Perceptual reuse candidates remain governed by the separate scan and human
decisions. The natural locked-set gate, controlled non-ticket gate, and derived
relationship gate must all pass.

After completing any required `decisions`, bind the review package. Binding
uses the formal data root created by `prepare-candidate` and validates the
unchanged sealed quality evidence, persisted source authority, manifest, scan,
decisions, and code-generated relationship suite before writing output. It
remains offline and does not start OCR:

```powershell
.\.venv\Scripts\python.exe tools\loop7_locked_set_release.py bind-review `
  --data-root C:\path\to\DaHeLockedSetFormalData `
  --review-package C:\isolated\loop7-review-prepared.json `
  --output C:\isolated\loop7-review-bound.json
```

If any decision is `duplicate`, validation stops before OCR. Replace the
affected candidate with unseen evidence, complete the human review again, and
publish a new seal; do not relabel the duplicate as distinct to continue.

`bind-review` has already run the fail-closed validation. Run `validate` to
reproduce that check and write a standalone pre-OCR validation record:

```powershell
.\.venv\Scripts\python.exe tools\loop7_locked_set_release.py validate `
  --data-root C:\path\to\DaHeLockedSetFormalData `
  --dataset-id LOCKED_DATASET_ID `
  --review-package C:\isolated\loop7-review-bound.json `
  --output C:\isolated\loop7-review-validation.json
```

Only a `ready_for_ocr_evaluation` result may enter formal evaluation:

```powershell
.\.venv\Scripts\python.exe tools\loop7_locked_set_release.py evaluate `
  --data-root C:\path\to\DaHeLockedSetFormalData `
  --development-data-root C:\path\to\DaHeDevelopmentData `
  --dataset-id LOCKED_DATASET_ID `
  --review-package C:\isolated\loop7-review-bound.json `
  --actor REVIEWER_ID `
  --idempotency-key UNIQUE_FORMAL_EVALUATION_KEY `
  --report-output C:\isolated\loop7-formal-report.json
```

`evaluate` locks and revalidates both roots again. A changed development
manifest, exclusion inventory, shadow pointer, evaluation, lifecycle attempt,
template definition, source authority, execution authority, or rollover
binding stops before formal OCR. The command
accepts only a factory-qualified local OCR composition.
The formal report binds the full OCR composition evidence, runtime set,
application build, matcher, policy, template set, exclusion snapshot,
similarity scan, human review package, 100 real-image results, 50 real-pair
results, and all four derived relationship outcomes. The application-build
evidence contains an explicit versioned manifest of the formal decision and OCR
orchestration sources, including the offline formal-authority release entry
point, Alembic configuration, and the applied SQLite migration chain, with one
logical path and SHA-256 per file. The manifest is stored in the run context and
its canonical SHA-256 must equal
`application_build_sha256`; a missing or unreadable listed source stops before
formal OCR, and any listed source change prevents an older formal report from
replaying. The list is deliberately limited to the formal backend pipeline and
does not hash the frontend, documentation, temporary output, or the whole
repository. The upstream legacy candidate discovery tool is also excluded:
its output is frozen and independently revalidated by the candidate seal and
persisted source authority before it can enter this formal chain. SQLite stores
the canonical human quality records, near-duplicate decisions, and
derived-suite evidence, not only their hashes; online backup and restore retain
them.

If any real or derived locked-set result influences code, preprocessing,
configuration, templates, models, thresholds, rules, mappings, adapters, error
handling, or a label, permanently invalidate the real locked set before making
the change:

```powershell
.\.venv\Scripts\python.exe tools\loop7_locked_set_release.py invalidate `
  --data-root C:\path\to\DaHeLockedSetFormalData `
  --dataset-id LOCKED_DATASET_ID `
  --expected-record-version RECORD_VERSION_FROM_THE_LAST_OUTPUT `
  --influence-kind template `
  --reason "Describe the change influenced by the locked-set result." `
  --actor REVIEWER_ID `
  --idempotency-key UNIQUE_INVALIDATION_KEY `
  --output .\.tmp\loop7-invalidation.json
```

Invalidation is append-only, moves all 100 images into development exclusion,
and prevents the old formal accuracy claim from being replayed. A new unseen
locked set is then required. No command accesses Chengfeng or any network;
only `evaluate` starts local OCR. A passed locked-set report still writes
`loop_7_accepted: false`: independent evidence review and the Loop ledger
remain required. A local 50-waybill candidate review package may exist, but it
does not count as a locked set until every sample is independently reviewed,
all replacements are resolved, and the bound formal workflow passes. Loop 7
is now closed only by the recorded waiver in `verification/loop-ledger.json`;
the failed gate remains failed and none of the prohibited acceptance claims
becomes valid.

## Run the offline console

Build and verify the application first, then start the local console:

```powershell
.\.venv\Scripts\python.exe tools\check.py
.\.venv\Scripts\python.exe -m dahe --serve
```

The application binds only to `127.0.0.1:8877` and opens the system default
browser. The single normal audit uses the same cooperative task engine and
resource accounting as the protected scheduler fixtures. Its platform data and
audit inputs are deterministic fakes; the console does not log in to Chengfeng
or process production documents. Starting with `--enable-test-fixtures` keeps
the isolated fixture console on fake OCR and does not start local OCR workers.

For the operator-console browser checks, start an isolated fixture console on
an unused loopback port, then run Playwright against that exact origin:

```powershell
.\.venv\Scripts\python.exe -m dahe --serve `
  --data-root "$env:LOCALAPPDATA\Temp\DaHeConsoleE2E" `
  --port 8899 `
  --enable-test-fixtures `
  --no-browser

$env:DAHE_E2E_BASE_URL = "http://127.0.0.1:8899"
npm.cmd --prefix frontend run test:e2e
```

The Playwright checks use the installed Microsoft Edge channel and isolated
fake API fixtures. They do not contact Chengfeng or open legacy data.

## Loop 5 frozen Chengfeng contract

The checked-in Loop 5 fixture supports exactly three offline read operations:
waybill list, waybill detail, and ticket image download. Every request must
match the synthetic manifest's origin, path, method, parameter location, keys,
values, and value types. Redirects and all unknown or write operations are
denied.

The fixture origin ends in `.invalid`, the replay transport never opens a
socket, and normal application configuration cannot enable real platform
access. A future real adapter requires a separately approved read-only capture
window and a sanitized contract; this build is not evidence that the synthetic
endpoints match Chengfeng production.

Each atomic replay read crosses the versioned NDJSON command/result boundary.
The main process correlates the result to its command, rechecks browser
authority, and verifies the staged path, hash, size, and media signature before
accepting immutable bytes. Command staging is removed after consumption and
safe orphan staging is recovered when the isolated runtime starts. Images then
enter the content-addressed evidence store and SQLite reference/checkpoint
transaction; a restart resumes only the last uncommitted read.

The durable SQLite database is stored at
`<data-root>\database\dahe.sqlite3`. It is managed only through checked-in
Alembic migrations, with WAL, foreign keys, a busy timeout, and integrity
checks enabled. Evidence files use content-addressed paths under
`<data-root>\evidence`.

To inspect the protected Loop 3 multi-task fixtures, use an explicit isolated
data directory:

```powershell
.\.venv\Scripts\python.exe -m dahe --serve `
  --data-root .\.tmp\loop3-console `
  --enable-test-fixtures
```

The protected switch is rejected without `--data-root`. Fixture mode
permanently marks and binds an empty data root to that purpose; an existing
unmarked or mismatched root is rejected instead of being repurposed. The long
audit, short audit, and loading probe are non-production exercises and remain unavailable
from the normal console.

The fixed Loop 9 browser-close, transient-network, application-restart, and
GPU-worker fault scenarios run through the real scheduler in the same formal
Loop 9 Chengfeng-shadow data root used by the later operational-evidence
replay. Stop the main console first. The tool acquires the installation's
single-instance guard, requires a verified selected read contract, current
database head, and a current-build production-shadow access authority, then
runs only internally generated `test_fixture` jobs. The command accepts no
result, count, duration, attempt, checkpoint, instance, job, or run identifiers
from the caller:

```powershell
.\.venv\Scripts\python.exe tools\loop9_run_fault_injections.py `
  --data-root C:\absolute\DaHeLoop9Data
```

The tool writes the real Job, WorkItem, StageAttempt, Checkpoint, Lease,
ApplicationInstance, and three-event Outbox transitions to that formal data
root. Repeating the command replays the same identities without adding rows.
It does not mark or convert the formal root into a fixture root, enable a
platform access window, construct a browser/live connector, or open a network
connection. An uninitialized, ordinary, stale-build, fixture-marked, or
currently running data root is rejected before scheduler writes.

After the four fault scenarios, the current-build locked-set Job, real-shadow
Job, daily triplet, dataset-isolation evidence, and their request-audit seals
all exist, build the immutable operational evidence. Use the exact run and Job
identities printed by the fault-injection command; do not invent replacements:

```powershell
.\.venv\Scripts\python.exe tools\loop9_build_operational_evidence.py `
  --data-root C:\absolute\DaHeLoop9Data `
  --locked-job-id LOCKED_AUDIT_JOB_ID `
  --real-shadow-selection-sha256 SHADOW_SELECTION_SHA256 `
  --real-shadow-job-id SHADOW_AUDIT_JOB_ID `
  --real-shadow-machine-evaluation-sha256 SHADOW_MACHINE_EVALUATION_SHA256 `
  --daily-snapshot-validation-sha256 DAILY_TRIPLET_SHA256 `
  --dataset-isolation-sha256 DATASET_ISOLATION_SHA256 `
  --browser-closed-run-id BROWSER_CLOSED_RUN_ID `
  --browser-closed-job-id BROWSER_CLOSED_JOB_ID `
  --gpu-worker-failure-run-id GPU_FAILURE_RUN_ID `
  --gpu-worker-failure-job-id GPU_FAILURE_JOB_ID `
  --main-application-restart-run-id APP_RESTART_RUN_ID `
  --main-application-restart-job-id APP_RESTART_JOB_ID `
  --transient-network-failure-run-id NETWORK_FAILURE_RUN_ID `
  --transient-network-failure-job-id NETWORK_FAILURE_JOB_ID
```

The last command is the only entry point that may set Loop 9 to
`shadow_accepted`. It performs a fresh offline replay while holding the Ledger
lock, publishes content-addressed evidence under the repository's fixed Loop 9
formal directory, and updates only the repository Ledger. Run it from this
repository with the console stopped:

```powershell
.\.venv\Scripts\python.exe tools\loop9_final_acceptance.py `
  --data-root C:\absolute\DaHeLoop9Data `
  --ledger C:\absolute\DaHeRepository\verification\loop-ledger.json `
  --output-directory C:\absolute\DaHeRepository\verification\loops\loop-9\formal `
  --read-contract-validation C:\absolute\evidence\read-contract-validation.json `
  --current-locked-selection-sha256 LOCKED_SELECTION_SHA256 `
  --real-shadow-selection-sha256 SHADOW_SELECTION_SHA256 `
  --real-shadow-package C:\absolute\evidence\shadow-30-review-package `
  --real-shadow-seal C:\absolute\evidence\shadow-30-human-review-seal.json `
  --real-shadow-machine-evaluation C:\absolute\evidence\shadow-30-machine-evaluation.json `
  --daily-snapshot-validation C:\absolute\evidence\daily-triplet.json `
  --discovery-development C:\absolute\evidence\discovery.json `
  --current-locked-50 C:\absolute\evidence\locked-50.json `
  --real-shadow-30 C:\absolute\evidence\shadow-30.json `
  --daily-validation-dataset C:\absolute\evidence\daily.json `
  --source-development-authority C:\absolute\evidence\source-development-authority.json `
  --dataset-isolation C:\absolute\evidence\dataset-isolation.json `
  --formal-run-evidence-sha256 FORMAL_RUN_EVIDENCE_SHA256 `
  --locked-job-id LOCKED_AUDIT_JOB_ID `
  --real-shadow-job-id SHADOW_AUDIT_JOB_ID `
  --browser-closed-run-id BROWSER_CLOSED_RUN_ID `
  --browser-closed-job-id BROWSER_CLOSED_JOB_ID `
  --gpu-worker-failure-run-id GPU_FAILURE_RUN_ID `
  --gpu-worker-failure-job-id GPU_FAILURE_JOB_ID `
  --main-application-restart-run-id APP_RESTART_RUN_ID `
  --main-application-restart-job-id APP_RESTART_JOB_ID `
  --transient-network-failure-run-id NETWORK_FAILURE_RUN_ID `
  --transient-network-failure-job-id NETWORK_FAILURE_JOB_ID `
  --expected-ledger-revision CURRENT_LEDGER_REVISION
```

The command rejects a copied Ledger, a different output directory, stale
revision, noncanonical evidence, failed Gate, or source/build drift. It makes no
Chengfeng or other network request. Do not run it until every real 50+30 and
daily Gate has actually passed.

Earlier development databases at
`<data-root>\runtime\loop2-temporary.sqlite3` are ignored. They are never
migrated, opened, or deleted by the current application. An existing formal
database without a recognized Alembic identity is rejected without mutation.
