// AnyPhraseRecovery v0.4.4 — sweep funds out of a compromised webWallet seed and restore
// the host node back to its original state.
//
// The flow REQUIRES two node restarts (after each megammrsync). State is persisted to
// localStorage so the dapp can resume exactly where it left off after each restart.
//
// The compromised seed never leaves this device. The only data sent off-device is the
// megammrsync RPC traffic to one of four known megammr hosts (or a custom one chosen
// by the user under Advanced).

// ============================================================================
// Config
// ============================================================================

const HOSTS = [
  "eurobuddha.com:9001",
  "spartacusrex.com:9001",
  "minimammr.com:9001",
  "megammr.minima.global:9001",
];
const KEYUSES = 2500;                                   // user-specified (matches original plan)
const STORAGE_KEY = "anyphrase.flow.v1";
const POST_SWEEP_WAIT_SECONDS = 60;                     // wait for send tx to be mined before restoring
const MEGAMMR_FILE_URL = "https://eurobuddha.com/mega.mmr";
const MEGAMMR_LOCAL_FILENAME = "mega.mmr";

// ============================================================================
// State
// ============================================================================
//
// state.stage values used as persisted resume points:
//   null / undefined        — no flow in progress; show welcome
//   "import_sync_pending"   — megammrsync(import) just issued; node will reboot.
//                             On resume: load balance, show sweep step.
//   "swept"                 — sweep complete; ready to issue restore megammrsync.
//                             On resume: show restore step (in case user closed dapp).
//   "restore_sync_pending"  — megammrsync(restore) just issued; node will reboot.
//                             On resume: run verification automatically.
//   "verified"              — flow complete. Show done screen, offer reset.

const state = {
  // PERSISTED
  stage: null,
  selectedHost: null,
  backupFile: null,             // absolute path returned by `backup` response
  backupPassword: null,
  destinationMx: null,          // captured BEFORE any megammrsync
  hostFingerprint: null,        // sha256[:16] of sorted default-Mx list

  // PERSISTED — remembers when the post-sweep cooldown finishes so revisits skip the wait
  restoreReadyAt: null,

  // EPHEMERAL (per-session) — these are rebuilt on resume by the relevant enter*Step()
  compromisedSeed: null,        // only used to issue megammrsync, never persisted
  customDest: null,
  balances: [],
  importedAddresses: [],        // rebuilt by loadSweepBalance() on resume
  megammrDownloadPath: null,    // captured from MDS.file.download response (megammr tab)
};

// ============================================================================
// Persistence
// ============================================================================

function savePersisted() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      stage: state.stage,
      selectedHost: state.selectedHost,
      backupFile: state.backupFile,
      backupPassword: state.backupPassword,
      destinationMx: state.destinationMx,
      hostFingerprint: state.hostFingerprint,
      restoreReadyAt: state.restoreReadyAt,
    }));
  } catch (_e) { /* localStorage may be unavailable; flow degrades but won't crash */ }
}

function loadPersisted() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch (_e) {
    return null;
  }
}

function clearPersisted() {
  try { localStorage.removeItem(STORAGE_KEY); } catch (_e) {}
  state.stage = null;
  state.selectedHost = null;
  state.backupFile = null;
  state.backupPassword = null;
  state.destinationMx = null;
  state.hostFingerprint = null;
  state.restoreReadyAt = null;
  state.megammrDownloadPath = null;
}

function persistedAsString() {
  const p = loadPersisted();
  if (!p) return "(none)";
  // mask the password
  const safe = Object.assign({}, p);
  if (safe.backupPassword) safe.backupPassword = "<" + safe.backupPassword.length + " chars>";
  return JSON.stringify(safe, null, 2);
}

// ============================================================================
// Helpers
// ============================================================================

function $(id) { return document.getElementById(id); }

function setStatus(elId, text, kind) {
  const el = $(elId);
  if (!el) return;
  el.textContent = text || "";
  el.className = "status" + (kind ? " " + kind : "");
}

// flashStatus shows a transient message in `elId` and restores the original text+class
// after 1.6s. Unlike setStatus, this preserves the element's existing className so it
// can be safely called on banner-styled elements (welcome-perm-warn, etc).
function flashStatus(elId, text, kind) {
  const el = $(elId);
  if (!el) return;
  const prevText = el.textContent;
  const prevClass = el.className;
  el.textContent = text;
  if (kind && el.className.indexOf(kind) < 0) el.className = (prevClass + " " + kind).trim();
  setTimeout(() => {
    if (el.textContent === text) { el.textContent = prevText; el.className = prevClass; }
  }, 1600);
}

function copyText(text) {
  if (!text) return Promise.resolve(false);
  if (navigator.clipboard && navigator.clipboard.writeText) {
    return navigator.clipboard.writeText(text).then(() => true).catch(() => fallbackCopy(text));
  }
  return Promise.resolve(fallbackCopy(text));
}

function fallbackCopy(text) {
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.left = "-9999px";
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
  document.body.removeChild(ta);
  return ok;
}

// ============================================================================
// Diagnostic logging — captures every MDS request/response so users can copy
// and share it for debugging.
// ============================================================================

const DIAG_MAX_CHARS = 50000;
const DIAG_TRIM_TO   = 40000;

function diagLog(direction, payload) {
  const el = document.getElementById("diag-log");
  if (!el) return;
  const ts = new Date().toISOString().slice(11, 19);
  let s;
  if (typeof payload === "string") {
    s = payload.length > 500 ? payload.slice(0, 500) + "…(truncated)" : payload;
  } else {
    try {
      s = JSON.stringify(payload, (k, v) => {
        // Mask secrets in diag output
        if (k === "phrase" || k === "password") return "<hidden>";
        return v;
      });
      if (s.length > 800) s = s.slice(0, 800) + "…(truncated)";
    } catch (_e) { s = String(payload); }
  }
  // Cap buffer size — long sessions otherwise leak memory and slow rendering
  let cur = el.textContent;
  if (cur.length > DIAG_MAX_CHARS) cur = "…(older entries trimmed)\n" + cur.slice(-DIAG_TRIM_TO);
  el.textContent = cur + `[${ts}] ${direction} ${s}\n`;
  el.scrollTop = el.scrollHeight;
}

// Sanitize a command string for diag/log display — masks any phrase: or password: arg
function maskCommand(c) {
  return String(c)
    .replace(/phrase:"[^"]*"/g, 'phrase:"<hidden>"')
    .replace(/password:\S+/g, "password:<hidden>");
}

// ============================================================================
// Sticky pending bar + Universal-Casino-style pending registry
//
// Architecture:
//   1. Every cmd() snapshots the pending list BEFORE issuing, so we can identify
//      our own UID after the fact even when the response doesn't surface it.
//   2. Pending detection is truthy on r.pending (not strict ===true), plus the
//      error-string regex fallback.
//   3. waitForPendingResolution shows the sticky banner and NEVER auto-hides on
//      unknown UID — the user has a manual "I approved it" button always available.
//   4. For megammrsync (long-running async), pending-removed is the APPROVAL signal,
//      not the COMPLETION signal. We then wait MEGAMMRSYNC_RUN_SECONDS more before
//      resolving, with the banner showing "running on node — DO NOT restart yet".
//   5. Dismiss button rejects the awaiting Promise (PendingDismissedError) so the
//      caller sees a clean failure instead of hanging forever.
// ============================================================================

const MEGAMMRSYNC_RUN_SECONDS = 90;          // post-approval wait before allowing restart
const CMD_TIMEOUT_MS_DEFAULT = 60000;        // default per-cmd timeout
const CMD_TIMEOUT_MS_LONG    = 300000;       // for backup / megammrsync (5 min)

class PendingDismissedError extends Error {
  constructor() { super("Pending action dismissed by user"); this.name = "PendingDismissedError"; }
}

class CmdTimeoutError extends Error {
  constructor(c, ms) { super("MDS timeout after " + ms + "ms running " + (c.split(" ")[0] || c)); this.name = "CmdTimeoutError"; }
}

// Single in-flight pending operation. Multiple parallel pendings are not currently
// supported — the dapp's flow is strictly sequential, so this is fine.
let pendingState = {
  resolve: null,
  reject: null,
  uid: null,                // lowercase hex, or "(unknown)" if we can't identify it
  command: null,            // full command string
  label: null,              // short display label
  startedAt: null,          // ms epoch when banner went up
  approvedAt: null,         // ms epoch when UID disappeared from pending list (or manual)
  timer: null,              // setInterval handle for polling
  isLongRunning: false,     // true for megammrsync (post-approval wait required)
};

function clearPendingTimer() {
  if (pendingState.timer) { clearInterval(pendingState.timer); pendingState.timer = null; }
}

function resetPendingState() {
  clearPendingTimer();
  pendingState.resolve = null;
  pendingState.reject = null;
  pendingState.uid = null;
  pendingState.command = null;
  pendingState.label = null;
  pendingState.startedAt = null;
  pendingState.approvedAt = null;
  pendingState.isLongRunning = false;
}

function showPendingBar(label, uid, title) {
  $("pending-bar-title").textContent = title || "Approve in MiniHub Pending";
  $("pending-bar-cmd").textContent = label;
  $("pending-bar-uid").textContent = "uid " + (uid === "(unknown)" ? "(unknown — use 'I approved it' button)" : uid);
  $("pending-bar-poll").textContent = "…waiting";
  // The "I approved it" button is meaningful BEFORE approval is recorded.
  // Once approval is recorded (post-approval wait), hide it so the user can't
  // accidentally restart the wait clock.
  $("pending-bar-confirm").hidden = !!pendingState.approvedAt;
  $("pending-bar").hidden = false;
}

function hidePendingBar() {
  $("pending-bar").hidden = true;
  // Reset to default visibility so the next pending shows the button again
  $("pending-bar-confirm").hidden = false;
}

// Raw MDS.cmd with timeout. Bypasses the cmd() wrapper — used internally for polling.
function rawCmd(c, timeoutMs) {
  const t = timeoutMs || CMD_TIMEOUT_MS_DEFAULT;
  return Promise.race([
    new Promise(resolve => MDS.cmd(c, res => resolve(res))),
    new Promise((_, reject) => setTimeout(() => reject(new CmdTimeoutError(c, t)), t)),
  ]);
}

async function listPendingUids() {
  try {
    const r = await rawCmd("mds action:pending", 8000);
    if (!r) return [];
    const resp = r.response || {};
    // MDS may return the pending list as response.pending OR as response itself
    let arr = resp.pending || resp.list || (Array.isArray(resp) ? resp : null);
    if (!Array.isArray(arr)) return [];
    return arr
      .map(p => p && String(p.uid || p.id || p || "").toLowerCase())
      .filter(Boolean);
  } catch (_e) { return []; }
}

function isPendingResponse(r) {
  if (!r) return false;
  if (r.pending) return true;                    // truthy: covers true, "0xUID", obj
  const errMsg = r.error || "";
  if (errMsg && /pending|needs to be confirmed/i.test(errMsg)) return true;
  return false;
}

function extractPendingUid(r) {
  if (!r) return "(unknown)";
  if (r.uid) return String(r.uid).toLowerCase();
  if (typeof r.pending === "string") return r.pending.toLowerCase();
  if (r.pending && r.pending.uid) return String(r.pending.uid).toLowerCase();
  const errMsg = r.error || "";
  const m = errMsg.match(/0x[A-Fa-f0-9]{20,}/);
  if (m) return m[0].toLowerCase();
  return "(unknown)";
}

function isLongRunningCommand(c) {
  return /^megammrsync /.test(String(c).trim());
}

function waitForPendingResolution(commandStr, uid) {
  const label = (commandStr.split(" ")[0] || commandStr).slice(0, 32);
  const longRunning = isLongRunningCommand(commandStr);
  showPendingBar(label, uid, "Approve in MiniHub Pending");
  diagLog("PENDING", { command: label, uid: uid, longRunning: longRunning });

  return new Promise((resolve, reject) => {
    pendingState.resolve = resolve;
    pendingState.reject  = reject;
    pendingState.uid     = (uid || "").toLowerCase();
    pendingState.command = commandStr;
    pendingState.label   = label;
    pendingState.startedAt = Date.now();
    pendingState.isLongRunning = longRunning;

    if (pendingState.timer) clearInterval(pendingState.timer);
    pendingState.timer = setInterval(checkPendingResolution, 2000);
    // Do an immediate first check so the user doesn't wait 2s for the first poll
    checkPendingResolution();
  });
}

async function checkPendingResolution() {
  if (!pendingState.uid) return;        // already resolved
  const elapsed = Math.floor((Date.now() - pendingState.startedAt) / 1000);

  if (pendingState.approvedAt) {
    // Long-running command — post-approval wait
    const sincApproved = Math.floor((Date.now() - pendingState.approvedAt) / 1000);
    const remaining = MEGAMMRSYNC_RUN_SECONDS - sincApproved;
    if (remaining > 0) {
      $("pending-bar-poll").textContent =
        "approved — running on node, ~" + remaining + "s remaining (DO NOT restart yet)";
    } else {
      // post-approval wait complete — resolve as success
      finalisePendingSuccess();
    }
    return;
  }

  $("pending-bar-poll").textContent =
    pendingState.uid === "(unknown)"
      ? "waiting for you to click 'I approved it' (UID couldn't be auto-detected)"
      : "polling for approval (" + elapsed + "s elapsed)";

  if (pendingState.uid === "(unknown)") return;  // can't auto-detect; wait for manual button

  const uids = await listPendingUids();
  if (!uids.includes(pendingState.uid)) {
    // UID gone — approval (or denial) happened
    onPendingApproved();
  }
}

function onPendingApproved() {
  // IDEMPOTENT — guard against repeated calls (e.g. user clicking "I approved it"
  // again during the post-approval wait). Without this, approvedAt would reset
  // and the long-running countdown would restart from zero.
  if (pendingState.approvedAt) return;
  pendingState.approvedAt = Date.now();
  if (pendingState.isLongRunning) {
    showPendingBar(
      pendingState.label,
      pendingState.uid,
      "Approved — sync running on node (do NOT restart yet)"
    );
    // showPendingBar reads pendingState.approvedAt and hides the manual-approve
    // button accordingly. The poll timer keeps ticking; checkPendingResolution
    // will finalise after the post-approval wait elapses.
  } else {
    finalisePendingSuccess();
  }
}

function finalisePendingSuccess() {
  if (!pendingState.resolve) return;
  const resolve = pendingState.resolve;
  diagLog("PENDING-RESOLVED", { uid: pendingState.uid, label: pendingState.label });
  hidePendingBar();
  resetPendingState();
  resolve({ status: true, response: { pendingResolved: true } });
}

function onPendingManualApprove() {
  // User clicked "I approved it" — treat as approved immediately
  if (!pendingState.uid) return;
  diagLog("PENDING-MANUAL-APPROVE", { uid: pendingState.uid, label: pendingState.label });
  onPendingApproved();
}

function onPendingDismiss() {
  if (!pendingState.reject) {
    // No active pending — just hide the banner (defensive)
    hidePendingBar();
    return;
  }
  // If the command is long-running and already approved, the megammrsync is
  // ALREADY RUNNING on the node. Dismissing here makes the dapp think it failed
  // while the node continues. Warn the user before letting them dismiss.
  if (pendingState.approvedAt && pendingState.isLongRunning) {
    if (!confirm(
      "The sync is already running on the node and will complete on its own. " +
      "Dismissing here only tells the dapp to treat it as failed — it will not " +
      "stop the sync. Re-running the recovery while the previous sync is still " +
      "going can cause conflicts. Dismiss anyway?"
    )) return;
  }
  const reject = pendingState.reject;
  diagLog("PENDING-DISMISSED", { uid: pendingState.uid, label: pendingState.label });
  hidePendingBar();
  resetPendingState();
  reject(new PendingDismissedError());
}

// Read-only commands cannot go pending. Skip the listPendingUids round-trip for these.
const READ_ONLY_CMDS = new Set([
  "balance", "getaddress", "scripts", "status", "block", "history", "coins",
  "checkmode", "checkpending", "tokens", "txnlist", "keys",
  // sub-action only — these top-level commands have action variants we use as reads only
  "mds", "network", "maxima",
]);
function isReadOnlyCmd(c) {
  const head = (String(c).trim().split(/\s+/)[0] || "").toLowerCase();
  return READ_ONLY_CMDS.has(head);
}

async function cmd(c, opts) {
  opts = opts || {};
  const timeoutMs = opts.timeout
    || (isLongRunningCommand(c) || /^backup /.test(c) ? CMD_TIMEOUT_MS_LONG : CMD_TIMEOUT_MS_DEFAULT);

  diagLog("CMD→", maskCommand(c));
  // Snapshot pending list BEFORE issuing — used to identify our UID afterwards.
  // Skip for read-only commands: they can't pend, and the round-trip would slow
  // down every read with an extra MDS call.
  const beforeUids = isReadOnlyCmd(c) ? [] : await listPendingUids();

  let r;
  try {
    r = await rawCmd(c, timeoutMs);
  } catch (e) {
    diagLog("ERR←", e.message);
    throw e;
  }
  diagLog("RES←", r);

  if (isPendingResponse(r)) {
    let uid = extractPendingUid(r);
    if (uid === "(unknown)") {
      // Try the diff of pending lists
      const afterUids = await listPendingUids();
      const newUids = afterUids.filter(u => !beforeUids.includes(u));
      if (newUids.length === 1) uid = newUids[0];
      else if (newUids.length > 1) uid = newUids[newUids.length - 1];
    }
    return await waitForPendingResolution(c, uid);
  }

  if (r && r.status) return r;
  throw new Error((r && r.error) || ("command failed: " + (c.split(" ")[0] || c)));
}

// ============================================================================
// Live terminal — pipes MINIMALOG events to whichever log panel is currently active
// ============================================================================

let activeLogElId = null;
let activeLogStartTime = null;
let activeLogTimer = null;

function startLiveTerminal(elId, label) {
  activeLogElId = elId;
  activeLogStartTime = Date.now();
  appendLog(elId, "─".repeat(48));
  appendLog(elId, "▸ " + label);
  // tick every second to give a "still working" indication
  if (activeLogTimer) clearInterval(activeLogTimer);
  let lastTick = -1;
  activeLogTimer = setInterval(() => {
    const elapsed = Math.floor((Date.now() - activeLogStartTime) / 1000);
    if (elapsed === lastTick) return;
    lastTick = elapsed;
    // overwrite the heartbeat line so we don't fill the log with spam
    const el = $(elId);
    if (!el) return;
    const lines = el.textContent.split("\n");
    const fmt = "  …elapsed " + String(Math.floor(elapsed/60)).padStart(2,"0") + ":" + String(elapsed%60).padStart(2,"0");
    if (lines.length && lines[lines.length-1].startsWith("  …elapsed ")) {
      lines[lines.length-1] = fmt;
    } else {
      lines.push(fmt);
    }
    el.textContent = lines.join("\n");
    el.scrollTop = el.scrollHeight;
  }, 1000);
}

function stopLiveTerminal(message) {
  if (activeLogTimer) { clearInterval(activeLogTimer); activeLogTimer = null; }
  if (activeLogElId && message) appendLog(activeLogElId, "✓ " + message);
  activeLogElId = null;
  activeLogStartTime = null;
}

function appendLog(elId, line) {
  const el = $(elId);
  if (!el) return;
  // remove trailing heartbeat line if present so the new line goes above future heartbeats
  const lines = el.textContent.split("\n");
  if (lines.length && lines[lines.length-1].startsWith("  …elapsed ")) lines.pop();
  lines.push(line);
  el.textContent = lines.join("\n");
  el.scrollTop = el.scrollHeight;
}

function onMinimaLog(data) {
  if (!activeLogElId) return;
  // data may be a string or an object with .message
  const msg = (typeof data === "string") ? data
            : (data && (data.message || data.log || JSON.stringify(data)));
  if (!msg) return;
  // skip noise: only forward megammr / backup / restore / chain related logs
  appendLog(activeLogElId, "  • " + msg);
}

function show(stepId) {
  document.querySelectorAll(".step").forEach(s => s.classList.remove("active"));
  const el = $("step-" + stepId);
  if (el) el.classList.add("active");
  window.scrollTo(0, 0);
}

function showTab(name) {
  document.querySelectorAll(".tab").forEach(t =>
    t.classList.toggle("active", t.dataset.tab === name));
  document.querySelectorAll(".tab-panel").forEach(p =>
    p.classList.toggle("active", p.id === "tab-" + name));
}

function isHostString(s) { return /^[\w.-]+:\d+$/.test(s); }
function validMx(s) { return /^M[xX][0-9A-Za-z]{57,68}$/.test(s); }

// Webwallet seeds can be anything — 24 BIP-39 words OR a custom string. Just reject
// empty input and characters that would break MDS command parsing.
function validSeed(s) {
  if (!s) return false;
  if (s.length < 1) return false;
  if (s.indexOf('"') >= 0) return false;
  return true;
}

function genPassword(len) {
  len = len || 20;
  // omit easily-confused chars to make handwritten transcription reliable
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
  const buf = new Uint8Array(len);
  if (window.crypto && window.crypto.getRandomValues) {
    window.crypto.getRandomValues(buf);
  } else {
    for (let i = 0; i < len; i++) buf[i] = Math.floor(Math.random() * 256);
  }
  let out = "";
  for (let i = 0; i < len; i++) out += chars[buf[i] % chars.length];
  return out;
}

async function sha256hex(s) {
  const buf = new TextEncoder().encode(s);
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function computeWalletFingerprint() {
  const sR = await cmd("scripts");
  const arr = Array.isArray(sR.response) ? sR.response : [];
  const mxs = arr
    .filter(s => s && s.default && s.miniaddress)
    .map(s => s.miniaddress)
    .sort();
  if (!mxs.length) return null;
  const fp = await sha256hex(mxs.join("|"));
  return fp.slice(0, 16);
}

async function getDefaultAddressSet() {
  const sR = await cmd("scripts");
  const arr = Array.isArray(sR.response) ? sR.response : [];
  return new Set(arr
    .filter(s => s && s.default && s.miniaddress)
    .map(s => s.miniaddress));
}

function tokenName(b) {
  if (!b) return "?";
  if (b.tokenid === "0x00") return "MINIMA";
  const tok = b.token;
  if (tok && tok.name) {
    if (typeof tok.name === "object" && tok.name.name) return String(tok.name.name);
    if (typeof tok.name === "string") return tok.name;
  }
  return (b.tokenid || "?").slice(0, 12) + "…";
}

function detectPlatform() {
  const isAndroid = /Android/i.test(navigator.userAgent);
  document.querySelectorAll(".reboot-android").forEach(el => el.hidden = !isAndroid);
  document.querySelectorAll(".reboot-desktop").forEach(el => el.hidden = isAndroid);
}

// ============================================================================
// Step 0 — welcome
// ============================================================================

function onWelcomeStart() {
  // No persisted state at this point — but in case the user clicked Start over and
  // is starting fresh with stale state, clear it.
  clearPersisted();
  state.compromisedSeed = null;
  state.customDest = null;
  enterSnapshotStep();
}

// (onWelcomeClear is defined further down — uses flashStatus instead of blocking alert)

// ============================================================================
// Step 1 — snapshot
//
// IMPORTANT: this step deliberately does NOT read or display the host node's
// seed phrase. It only:
//   - calls `getaddress` to capture a destination address (default-wallet pubkeys
//     are stored unencrypted; this works on locked nodes too)
//   - calls `scripts` to capture a wallet fingerprint for post-restore verification
//   - calls `status` to detect whether the vault is locked (for a UI hint only)
//   - runs `backup file:<rand>.bak password:<rand>` to produce an encrypted snapshot
//     of whatever state the node currently has (locked or unlocked — backup honours
//     either; if locked, the bak is locked too)
// The user is responsible for having their own seed backup outside this dapp.
// ============================================================================

function enterSnapshotStep() {
  show("snapshot");
  state.backupFile = null;
  state.backupPassword = null;
  $("snap-backup-info").hidden = true;
  $("snap-pw-check").checked = false;
  $("snap-backup-btn").disabled = true;
  $("snap-continue-btn").disabled = true;
  $("snap-locked-warn").hidden = true;
  setStatus("snap-backup-status", "Reading this node's address & fingerprint (no seed access)…");
  $("snap-dest").textContent = "loading…";

  loadSnapshotData()
    .then(() => {
      setStatus("snap-backup-status", "");
      $("snap-backup-btn").disabled = false;
    })
    .catch(e => {
      setStatus("snap-backup-status",
        "Failed to probe this node: " + e.message +
        ". The dapp needs read access to getaddress, scripts and status — these all work on locked nodes too. Check the dapp's MDS permission.", "err");
    });
}

async function loadSnapshotData() {
  // Capture destination address from getaddress — this is one of the 64 default
  // addresses; it belongs to the host wallet and we'll sweep recovered funds back
  // to it. getaddress works on locked nodes (default pubkeys are stored unencrypted).
  const a = await cmd("getaddress");
  const ar = a.response || {};
  state.destinationMx = ar.miniaddress || ar.address || "";
  if (!state.destinationMx) throw new Error("getaddress returned no address");
  $("snap-dest").textContent = state.destinationMx;

  // Capture wallet fingerprint for post-restore verification. Works on locked nodes.
  state.hostFingerprint = await computeWalletFingerprint();

  // Show a friendly warning if the node is currently password-locked
  try {
    const s = await cmd("status");
    const locked = !!(s.response && s.response.locked);
    $("snap-locked-warn").hidden = !locked;
  } catch (_e) { /* not fatal */ }
}

function updateSnapshotEnabled() {
  const backupDone = !!state.backupFile && !!state.backupPassword;
  const pwOk = $("snap-pw-check").checked;
  $("snap-continue-btn").disabled = !(backupDone && pwOk);
}

async function onSnapBackup() {
  $("snap-backup-btn").disabled = true;
  setStatus("snap-backup-status", "Generating credentials…");

  // CRITICAL: generate credentials and display them FIRST, before issuing the command.
  // If pending happens (READ mode), the password must already be on screen.
  const pw = genPassword(20);
  const file = "anyphrase-" + Date.now() + ".bak";
  state.backupFile = file;        // tentative; overwritten with absolute path if cmd ran sync
  state.backupPassword = pw;
  $("snap-backup-info").hidden = false;
  $("snap-backup-file").textContent = file + "  (full path will appear after backup completes)";
  $("snap-backup-password").textContent = pw;
  // Persist immediately so a dapp close mid-backup still leaves recoverable state
  savePersisted();

  $("snap-backup-log").textContent = "";
  $("snap-backup-log").hidden = false;
  startLiveTerminal("snap-backup-log", "running backup");
  try {
    const c = "backup file:" + file + " password:" + pw;
    appendLog("snap-backup-log", "> " + c.replace(/password:\S+/, "password:<hidden>"));
    // cmd() blocks transparently if MDS goes pending — sticky banner + auto-poll.
    const r = await cmd(c);
    appendLog("snap-backup-log", JSON.stringify(r.response || r, null, 2));
    stopLiveTerminal("backup complete");
    // For a synchronously-run backup, the response carries the absolute path.
    // For a pending-then-approved backup, it doesn't — we keep the relative filename.
    const absolutePath = (((r.response || {}).backup) || {}).file || file;
    state.backupFile = absolutePath;
    $("snap-backup-file").textContent = absolutePath;
    // CRITICAL: persist NOW so the user can close+reopen the dapp without losing the
    // backup credentials they just wrote down.
    savePersisted();
    setStatus("snap-backup-status", "Backup complete. Write the password down before continuing.", "ok");
    updateSnapshotEnabled();
  } catch (e) {
    stopLiveTerminal();
    appendLog("snap-backup-log", "ERROR: " + e.message);
    // Reset state — don't leave stale credentials shown after a failure
    state.backupFile = null;
    state.backupPassword = null;
    $("snap-backup-info").hidden = true;
    savePersisted();
    if (e.name === "PendingDismissedError") {
      setStatus("snap-backup-status",
        "Backup was dismissed. The action is no longer queued. Click Run backup to try again.", "warn");
    } else {
      setStatus("snap-backup-status", "Backup failed: " + e.message + ". Click Run backup to try again.", "err");
    }
    $("snap-backup-btn").disabled = false;
    updateSnapshotEnabled();
  }
}

// ============================================================================
// Step 2 — paste compromised seed
// ============================================================================

function onSeedContinue() {
  const raw = ($("seed-input").value || "").trim();
  if (!validSeed(raw)) {
    setStatus("seed-status", "Seed cannot be empty and cannot contain a double-quote character.", "err");
    return;
  }
  // Store VERBATIM — webwallet derived keys from the literal string, no normalization
  state.compromisedSeed = raw;
  setStatus("seed-status", "");
  setupHostStep();
  show("sync");
}

// ============================================================================
// Step 3 — pick host + run megammrsync (the destructive import)
// ============================================================================

function setupHostStep() {
  const list = $("host-list");
  list.innerHTML = "";
  HOSTS.forEach(h => {
    const li = document.createElement("li");
    li.textContent = h;
    list.appendChild(li);
  });
  state.selectedHost = null;
  rotateHost();
  $("sync-log").textContent = "";
  $("sync-run-btn").disabled = false;
  setStatus("sync-status", "");
}

function rotateHost() {
  const candidates = HOSTS.filter(h => h !== state.selectedHost);
  state.selectedHost = candidates[Math.floor(Math.random() * candidates.length)];
  renderSelectedHost();
}

function renderSelectedHost() {
  $("selected-host").textContent = state.selectedHost || "—";
  document.querySelectorAll("#host-list li").forEach(li => {
    li.classList.toggle("selected", li.textContent === state.selectedHost);
  });
}

function onCustomHostSet() {
  const v = ($("custom-host-input").value || "").trim();
  if (!isHostString(v)) {
    setStatus("sync-status", "Custom host should look like host.example.com:9001", "err");
    return;
  }
  state.selectedHost = v;
  renderSelectedHost();
  setStatus("sync-status", "Using custom host: " + v, "warn");
}

async function onRunSync() {
  $("sync-run-btn").disabled = true;
  setStatus("sync-status",
    "Running megammrsync against " + state.selectedHost + " — this can take 1–2 minutes…");
  startLiveTerminal("sync-log", "megammrsync action:resync (importing compromised seed)");
  try {
    // Persist BEFORE issuing — covers the case where the command succeeds but the dapp
    // dies/closes before we reach the post-await code path.
    state.stage = "import_sync_pending";
    savePersisted();

    const phrase = state.compromisedSeed.replace(/"/g, '\\"');
    const c = "megammrsync action:resync host:" + state.selectedHost +
              ' phrase:"' + phrase + '"' +
              " anyphrase:true keyuses:" + KEYUSES;
    appendLog("sync-log", "> " + c.replace(/phrase:"[^"]*"/, 'phrase:"<hidden>"'));
    const r = await cmd(c);
    appendLog("sync-log", JSON.stringify(r.response || r, null, 2));
    stopLiveTerminal("sync complete");

    // The compromised seed is now in the node — we no longer need to keep it in memory
    state.compromisedSeed = null;

    setStatus("sync-status", "Sync complete. Restart Minima now.", "ok");
    enterReboot1();
  } catch (e) {
    stopLiveTerminal();
    appendLog("sync-log", "ERROR: " + e.message);
    setStatus("sync-status",
      'Sync failed: ' + e.message + '. Click "Try a different host", then "Run megammrsync" again.', "err");
    $("sync-run-btn").disabled = false;
    state.stage = null;
    savePersisted();
  }
}

// ============================================================================
// Reboot 1
// ============================================================================

function enterReboot1() {
  show("reboot1");
  $("reboot1-state").textContent = persistedAsString();
}

// ============================================================================
// Step 4 — sweep (entered after reboot 1)
// ============================================================================

async function enterSweepStep() {
  show("sweep");
  setStatus("sweep-loading-status", "Loading balance from the imported wallet…");
  $("sweep-dest").textContent = state.destinationMx || "(unknown — clear saved state and start over)";
  $("sweep-balance").innerHTML = "";
  $("sweep-confirm-block").hidden = true;
  $("sweep-empty-warn").hidden = true;
  $("sweep-dest-warn").hidden = true;
  $("sweep-results").innerHTML = "";
  $("sweep-next-row").hidden = true;
  $("sweep-status").textContent = "";

  try {
    await loadSweepBalance();
    setStatus("sweep-loading-status", "");
    if (state.balances.length === 0) {
      $("sweep-empty-warn").hidden = false;
    } else {
      $("sweep-confirm-block").hidden = false;
      // bind confirmation listeners (idempotent — once per fresh DOM)
      bindSweepConfirmListeners();
      updateSweepEnabled();
    }
  } catch (e) {
    setStatus("sweep-loading-status",
      "Failed to load balance: " + e.message + ". The node may not have rebooted yet — wait and reload this dapp.", "err");
  }
}

async function loadSweepBalance() {
  // After megammrsync, the node's wallet IS the imported one. Capture imported addresses
  // for the destination-equality guard.
  state.importedAddresses = Array.from(await getDefaultAddressSet());

  const bR = await cmd("balance");
  const bArr = Array.isArray(bR.response) ? bR.response : [];
  state.balances = bArr
    .map(b => ({
      tokenid: b.tokenid,
      sendable: b.sendable || b.confirmed || "0",
      confirmed: b.confirmed,
      name: tokenName(b),
    }))
    .filter(b => parseFloat(b.sendable) > 0);

  // Render
  const root = $("sweep-balance");
  root.innerHTML = "";
  if (state.balances.length === 0) {
    const row = document.createElement("div");
    row.className = "balance-row zero";
    row.innerHTML = '<span class="amt">—</span><span class="tok">No spendable balance found</span>';
    root.appendChild(row);
  } else {
    state.balances.forEach(b => {
      const row = document.createElement("div");
      row.className = "balance-row";
      const a = document.createElement("span");
      a.className = "amt";
      a.textContent = b.sendable;
      const t = document.createElement("span");
      t.className = "tok";
      t.textContent = b.name + (b.tokenid === "0x00" ? "" : "  (" + b.tokenid.slice(0, 14) + "…)");
      row.appendChild(a);
      row.appendChild(t);
      root.appendChild(row);
    });
  }
}

function bindSweepConfirmListeners() {
  // remove old listeners by replacing nodes (cheap idempotent rebind).
  // Also explicitly RESET the checked state — cloneNode preserves it, which would
  // otherwise let a previous run's checked boxes carry forward without fresh consent.
  ["confirm-verified", "confirm-final", "confirm-custom-dest"].forEach(id => {
    const old = $(id);
    if (!old) return;
    const fresh = old.cloneNode(true);
    fresh.checked = false;
    old.parentNode.replaceChild(fresh, old);
    fresh.addEventListener("change", updateSweepEnabled);
  });
}

function getDestination() {
  return state.customDest || state.destinationMx;
}

function updateSweepEnabled() {
  const dest = getDestination();
  const destClash = !!dest && state.importedAddresses.indexOf(dest) >= 0;
  $("sweep-dest-warn").hidden = !destClash;
  $("sweep-dest").textContent = dest;

  const hasBalance = state.balances.length > 0;
  const baseChecks = $("confirm-verified").checked && $("confirm-final").checked;
  const customCheck = !state.customDest || $("confirm-custom-dest").checked;
  $("sweep-go-btn").disabled = !!(destClash || !hasBalance || !baseChecks || !customCheck);
}

function onCustomDestSet() {
  const v = ($("custom-dest-input").value || "").trim();
  if (!validMx(v)) {
    setStatus("sweep-status", "That doesn't look like a valid Minima address (Mx…).", "err");
    return;
  }
  state.customDest = v;
  $("custom-dest-confirm-row").hidden = false;
  $("confirm-custom-dest").checked = false;
  setStatus("sweep-status", "Custom destination set: " + v + ".", "warn");
  updateSweepEnabled();
}

function onCustomDestClear() {
  state.customDest = null;
  $("custom-dest-confirm-row").hidden = true;
  $("confirm-custom-dest").checked = false;
  setStatus("sweep-status", "Reset destination to your wallet's address.", "ok");
  updateSweepEnabled();
}

function onSweepSkipRestore() {
  // user has nothing to sweep — go straight to restore
  state.stage = "swept";
  savePersisted();
  show("restore");
  enterRestoreStep();
}

async function onSweep() {
  const dest = getDestination();
  const root = $("sweep-results");
  root.innerHTML = "";
  $("sweep-go-btn").disabled = true;
  setStatus("sweep-status", "Sending…");
  let ok = 0, err = 0;
  for (const b of state.balances) {
    const row = document.createElement("div");
    row.className = "sweep-result";
    const lbl = document.createElement("span");
    lbl.className = "lbl";
    lbl.textContent = b.sendable + " " + b.name;
    const result = document.createElement("span");
    result.className = "result";
    result.textContent = "sending…";
    row.appendChild(lbl);
    row.appendChild(result);
    root.appendChild(row);
    try {
      const c = "send address:" + dest + " amount:" + b.sendable +
                (b.tokenid === "0x00" ? "" : " tokenid:" + b.tokenid);
      // cmd() handles pending transparently via the sticky banner + auto-polling.
      // If pending fires for this send, the row stays "sending…" until approved.
      result.textContent = "queued — see sticky banner if pending";
      const r = await cmd(c);
      row.classList.add("ok");
      result.textContent = "sent";
      ok++;
    } catch (e) {
      row.classList.add("err");
      result.textContent = "failed: " + e.message;
      err++;
    }
  }
  if (err === 0) {
    setStatus("sweep-status", "All " + ok + " transfer(s) submitted. Continue to restore.", "ok");
  } else {
    setStatus("sweep-status",
      ok + " ok, " + err + " failed. You can still continue to restore — but the failed token(s) remain at the compromised address.", "err");
  }
  state.stage = "swept";
  savePersisted();
  $("sweep-next-row").hidden = false;
}

function onSweepNext() {
  // If any token failed to send, warn before proceeding — funds remain at the
  // compromised wallet for any failed token and won't be recovered.
  const results = $("sweep-results");
  const failedRows = results ? results.querySelectorAll(".sweep-result.err").length : 0;
  if (failedRows > 0) {
    if (!confirm(
      failedRows + " token(s) failed to send and remain at the compromised address. " +
      "Continuing to restore now will leave them stranded. Continue anyway?"
    )) return;
  }
  show("restore");
  enterRestoreStep();
}

// ============================================================================
// Step 5 — restore via megammrsync(file:+password:)
// ============================================================================

let restoreCountdownTimer = null;

function enterRestoreStep() {
  $("restore-run-btn").disabled = true;
  $("restore-log").textContent = "";
  setStatus("restore-status", "");

  // Skip the wait if we're past the calculated ready-time (e.g. user revisited
  // the step after waiting once already, or resumed from persisted state).
  const readyAt = state.restoreReadyAt || (Date.now() + POST_SWEEP_WAIT_SECONDS * 1000);
  if (!state.restoreReadyAt) {
    state.restoreReadyAt = readyAt;
    savePersisted();
  }
  let remaining = Math.max(0, Math.ceil((readyAt - Date.now()) / 1000));

  if (remaining <= 0) {
    setStatus("restore-wait-status", "Ready to restore.", "ok");
    $("restore-run-btn").disabled = false;
    return;
  }

  setStatus("restore-wait-status",
    "Giving the chain " + remaining + "s to mine your sweep before restoring…", "warn");
  if (restoreCountdownTimer) clearInterval(restoreCountdownTimer);
  restoreCountdownTimer = setInterval(() => {
    remaining = Math.max(0, Math.ceil((readyAt - Date.now()) / 1000));
    if (remaining <= 0) {
      clearInterval(restoreCountdownTimer);
      restoreCountdownTimer = null;
      setStatus("restore-wait-status", "Ready to restore.", "ok");
      $("restore-run-btn").disabled = false;
    } else {
      setStatus("restore-wait-status",
        "Giving the chain " + remaining + "s to mine your sweep before restoring…", "warn");
    }
  }, 1000);
}

async function onRestoreRun() {
  $("restore-run-btn").disabled = true;
  setStatus("restore-status", "Restoring via megammrsync — this can take a minute…");
  startLiveTerminal("restore-log", "megammrsync action:resync (restoring from snapshot)");
  appendLog("restore-log", "> megammrsync action:resync host:" + state.selectedHost +
                          " file:" + state.backupFile + " password:<hidden>");
  try {
    state.stage = "restore_sync_pending";
    savePersisted();

    const c = "megammrsync action:resync host:" + state.selectedHost +
              " file:" + state.backupFile +
              " password:" + state.backupPassword;
    const r = await cmd(c);
    appendLog("restore-log", JSON.stringify(r.response || r, null, 2));
    stopLiveTerminal("restore complete");
    setStatus("restore-status", "Restore command returned. Restart Minima now.", "ok");
    show("reboot2");
  } catch (e) {
    stopLiveTerminal();
    appendLog("restore-log", "ERROR: " + e.message);
    setStatus("restore-status", "Restore failed: " + e.message, "err");
    $("restore-run-btn").disabled = false;
    state.stage = "swept";
    savePersisted();
  }
}

// ============================================================================
// Step 6 — verify (entered after reboot 2)
// ============================================================================

async function enterVerifyStep() {
  show("verify");
  $("verify-results").innerHTML = "";
  $("verify-success").hidden = true;
  $("verify-failure").hidden = true;
  setStatus("verify-status", "Checking…");

  let allOk = true;

  // Check 1: wallet fingerprint should match the original
  const r1 = renderVerifyRow("Wallet identity matches snapshot");
  try {
    const fp = await computeWalletFingerprint();
    if (fp === state.hostFingerprint) {
      r1.pass("fingerprint " + fp);
    } else {
      r1.fail("got " + fp + ", expected " + state.hostFingerprint);
      allOk = false;
    }
  } catch (e) {
    r1.fail(e.message);
    allOk = false;
  }

  // Check 2: destination is in the wallet (so the swept funds are spendable)
  const r2 = renderVerifyRow("Destination is in this wallet");
  try {
    const set = await getDefaultAddressSet();
    if (state.destinationMx && set.has(state.destinationMx)) {
      r2.pass(state.destinationMx);
    } else {
      r2.fail("destination NOT in default-script set after restore");
      allOk = false;
    }
  } catch (e) {
    r2.fail(e.message);
    allOk = false;
  }

  // Check 3: balance is queryable
  const r3 = renderVerifyRow("Balance responsive");
  try {
    const b = await cmd("balance");
    const arr = Array.isArray(b.response) ? b.response : [];
    const minimaB = arr.find(x => x.tokenid === "0x00");
    r3.pass(minimaB
      ? "Minima sendable: " + (minimaB.sendable || minimaB.confirmed || "0")
      : "(no Minima entry yet — may take a few blocks)");
  } catch (e) {
    r3.fail(e.message);
    allOk = false;
  }

  // Surface lock status after restore — the wallet returns to its prior lock state
  try {
    const s = await cmd("status");
    const locked = !!(s.response && s.response.locked);
    $("verify-locked-reminder").hidden = !locked;
  } catch (_e) { /* not fatal */ }

  if (allOk) {
    state.stage = "verified";
    savePersisted();
    $("verify-success").hidden = false;
    setStatus("verify-status", "Recovery complete.", "ok");
  } else {
    $("verify-failure").hidden = false;
    $("verify-failure-cmd").textContent =
      "megammrsync action:resync host:" + (state.selectedHost || "<host>") +
      " file:" + (state.backupFile || "<backup>") +
      " password:" + (state.backupPassword || "<password>");
    $("verify-failure-state").textContent = persistedAsString();
    setStatus("verify-status", "Verification failed — see options below.", "err");
  }
}

function renderVerifyRow(label) {
  const root = $("verify-results");
  const row = document.createElement("div");
  row.className = "verify-result";
  const lbl = document.createElement("span");
  lbl.className = "lbl";
  lbl.textContent = label;
  const result = document.createElement("span");
  result.className = "result";
  result.textContent = "checking…";
  row.appendChild(lbl);
  row.appendChild(result);
  root.appendChild(row);
  return {
    pass(msg) { row.classList.add("ok"); result.textContent = "✓ " + msg; },
    fail(msg) { row.classList.add("err"); result.textContent = "✗ " + msg; },
  };
}

function onFinishRestart() {
  if (confirm("Clear saved state and start a new recovery?")) {
    clearPersisted();
    location.reload();
  }
}

function onWelcomeClear() {
  clearPersisted();
  flashStatus("welcome-perm-warn", "Saved state cleared. Click Get started to begin a fresh recovery.", "ok");
  show("welcome");
}

// ============================================================================
// MEGAMMR HOST TAB
// ============================================================================

async function mmDetect() {
  setStatus("mm-detect-status", "Probing…");
  $("mm-detect-btn").disabled = true;
  try {
    await cmd("megammr action:info");
    setStatus("mm-detect-status", "MegaMMR mode is active on this node.", "ok");
    $("mm-download-btn").disabled = false;
  } catch (_e) {
    setStatus("mm-detect-status",
      "MegaMMR mode is NOT active. Restart your Minima node with -megammr in the startup arguments, then click Detect again.",
      "err");
    $("mm-download-btn").disabled = true;
  } finally {
    $("mm-detect-btn").disabled = false;
  }
}

async function mmDownload() {
  setStatus("mm-download-status", "Downloading " + MEGAMMR_FILE_URL + " — large file, please wait…");
  $("mm-download-btn").disabled = true;
  try {
    diagLog("FILE.download→", { url: MEGAMMR_FILE_URL });
    // Race the download against a 5-minute timeout — without it, an unreachable
    // URL or a stalled download where the callback never fires hangs the dapp.
    const res = await Promise.race([
      new Promise((resolve, reject) => {
        MDS.file.download(MEGAMMR_FILE_URL, function (res) {
          diagLog("FILE.download←", res);
          if (res && res.status) resolve(res);
          else reject(new Error((res && res.error) || "download failed"));
        });
      }),
      new Promise((_, rej) => setTimeout(() => rej(new Error("download timeout (5 minutes)")), 300000)),
    ]);
    // Capture any path the download response gave us — saves a getpath call
    const r = res.response || {};
    if (r.file || r.path || r.fullpath) {
      state.megammrDownloadPath = r.file || r.path || r.fullpath;
    }
    setStatus("mm-download-status", "Download complete. Saved to dapp folder.", "ok");
    $("mm-import-btn").disabled = false;
  } catch (e) {
    setStatus("mm-download-status", "Download failed: " + e.message, "err");
    $("mm-download-btn").disabled = false;
  }
}

// Three-layer defence to find the absolute path of the downloaded mega.mmr:
//   1. The path returned by the download response (captured above)
//   2. MDS.file.getpath
//   3. MDS.file.list — enumerate the dapp folder, find by name
async function resolveMmrPath() {
  // Layer 1
  if (state.megammrDownloadPath) {
    diagLog("FILE.resolve(layer1)", state.megammrDownloadPath);
    return state.megammrDownloadPath;
  }
  // Layer 2
  try {
    const path = await new Promise((resolve, reject) => {
      diagLog("FILE.getpath→", { name: MEGAMMR_LOCAL_FILENAME });
      MDS.file.getpath(MEGAMMR_LOCAL_FILENAME, function (res) {
        diagLog("FILE.getpath←", res);
        if (res && res.status) {
          const r = res.response || {};
          const p = r.path || r.fullpath || r.absolute ||
            (typeof res.response === "string" ? res.response : null);
          if (p) return resolve(p);
        }
        reject(new Error("getpath returned no usable path"));
      });
    });
    diagLog("FILE.resolve(layer2)", path);
    return path;
  } catch (_e) { /* fall through to layer 3 */ }
  // Layer 3
  try {
    const list = await new Promise((resolve, reject) => {
      diagLog("FILE.list→", { dir: "/" });
      MDS.file.list("/", function (res) {
        diagLog("FILE.list←", res);
        if (res && res.status) resolve(res.response || []);
        else reject(new Error("list failed"));
      });
    });
    const arr = Array.isArray(list) ? list : (list.files || list.list || []);
    const match = arr.find(f => {
      const n = (f && (f.name || f.filename || (typeof f === "string" ? f : ""))) || "";
      return n === MEGAMMR_LOCAL_FILENAME || n.endsWith("/" + MEGAMMR_LOCAL_FILENAME);
    });
    if (match) {
      const path = match.path || match.fullpath || match.name || match;
      diagLog("FILE.resolve(layer3)", path);
      return path;
    }
  } catch (_e) { /* fall through */ }
  throw new Error("could not resolve path for " + MEGAMMR_LOCAL_FILENAME +
    " — see diagnostic console (above) for raw responses, or paste the absolute path manually below");
}

async function mmImport() {
  setStatus("mm-import-status", "Resolving file path…");
  $("mm-import-btn").disabled = true;
  try {
    let fullPath = ($("mm-manual-path") && $("mm-manual-path").value || "").trim();
    if (!fullPath) fullPath = await resolveMmrPath();
    setStatus("mm-import-status", "Importing from " + fullPath + " — can take a few minutes…");
    await cmd("megammr action:import file:" + fullPath);
    setStatus("mm-import-status",
      "Import complete. This node is now running a MegaMMR — once it finishes catching up, others can sync from it.",
      "ok");
  } catch (e) {
    setStatus("mm-import-status", "Import failed: " + e.message, "err");
    // Surface the manual-path input so the user can recover from a path-resolution failure
    if ($("mm-manual-path-row")) $("mm-manual-path-row").hidden = false;
    $("mm-import-btn").disabled = false;
  }
}

async function mmNetinfo() {
  $("mm-netinfo").textContent = "Loading…";
  try {
    const [maxR, , statusR] = await Promise.all([
      cmd("maxima action:info").catch(() => null),
      cmd("network action:list").catch(() => null),
      cmd("status").catch(() => null),
    ]);
    const lines = [];
    if (statusR && statusR.response && statusR.response.chain) {
      lines.push("chain top block: " + statusR.response.chain.block);
    }
    if (maxR && maxR.response) {
      const m = maxR.response;
      lines.push("maxima local: " + (m.local || m.contact || "(none)"));
      if (m.publickey) lines.push("maxima publickey: " + m.publickey);
    }
    lines.push("");
    lines.push("DM these details to @eurobuddha to be added to the Recovery host pool.");
    $("mm-netinfo").textContent = lines.join("\n") || "(no info available)";
  } catch (e) {
    $("mm-netinfo").textContent = "Failed: " + e.message;
  }
}

// ============================================================================
// Wiring + boot
// ============================================================================

function wireUp() {
  document.querySelectorAll(".tab").forEach(t =>
    t.addEventListener("click", () => showTab(t.dataset.tab)));

  // Step 0
  $("welcome-start-btn").addEventListener("click", onWelcomeStart);
  $("welcome-clear-btn").addEventListener("click", onWelcomeClear);

  // Step 1
  $("snap-back-btn").addEventListener("click", () => show("welcome"));
  $("snap-pw-check").addEventListener("change", updateSnapshotEnabled);
  $("snap-backup-btn").addEventListener("click", onSnapBackup);
  $("snap-copyfile-btn").addEventListener("click", () =>
    copyText(state.backupFile).then(ok =>
      flashStatus("snap-backup-status", ok ? "Copied file path." : "Copy failed.")));
  $("snap-copypw-btn").addEventListener("click", () =>
    copyText(state.backupPassword).then(ok =>
      flashStatus("snap-backup-status", ok ? "Copied password (write it on paper)." : "Copy failed.")));
  $("snap-continue-btn").addEventListener("click", () => show("seed"));

  // Step 2
  $("seed-back-btn").addEventListener("click", () => show("snapshot"));
  $("seed-continue-btn").addEventListener("click", onSeedContinue);

  // Step 3
  $("rotate-host-btn").addEventListener("click", rotateHost);
  $("custom-host-set-btn").addEventListener("click", onCustomHostSet);
  $("sync-back-btn").addEventListener("click", () => show("seed"));
  $("sync-run-btn").addEventListener("click", onRunSync);

  // Step 4
  $("custom-dest-set-btn").addEventListener("click", onCustomDestSet);
  $("custom-dest-clear-btn").addEventListener("click", onCustomDestClear);
  $("sweep-go-btn").addEventListener("click", onSweep);
  $("sweep-next-btn").addEventListener("click", onSweepNext);
  $("sweep-skip-restore-btn").addEventListener("click", onSweepSkipRestore);

  // Step 5
  $("restore-run-btn").addEventListener("click", onRestoreRun);

  // Sticky pending bar — dismiss rejects the awaiting Promise (so caller can
  // surface a clean error); confirm fast-paths the resolution.
  $("pending-bar-dismiss").addEventListener("click", onPendingDismiss);
  $("pending-bar-confirm").addEventListener("click", onPendingManualApprove);
  $("diag-clear-btn").addEventListener("click", () => { $("diag-log").textContent = ""; });
  $("diag-copy-btn").addEventListener("click", () =>
    copyText($("diag-log").textContent).then(ok =>
      alert(ok ? "Diagnostics copied to clipboard." : "Copy failed.")));

  // Step 6
  $("finish-restart-btn").addEventListener("click", onFinishRestart);

  // MegaMMR tab
  $("mm-detect-btn").addEventListener("click", mmDetect);
  $("mm-download-btn").addEventListener("click", mmDownload);
  $("mm-import-btn").addEventListener("click", mmImport);
  $("mm-netinfo-btn").addEventListener("click", mmNetinfo);
  $("mm-netinfo-copy-btn").addEventListener("click", () =>
    copyText($("mm-netinfo").textContent).then(ok =>
      flashStatus("mm-detect-status", ok ? "Copied." : "Copy failed.")));
}

function resumeFromPersisted() {
  const p = loadPersisted();
  if (!p || !p.stage) {
    show("welcome");
    return;
  }
  Object.assign(state, p);
  diagLog("RESUME", { stage: p.stage });
  switch (p.stage) {
    case "import_sync_pending":
      // node has been rebooted (else MDS wouldn't be inited). Resume to sweep.
      enterSweepStep();
      break;
    case "swept":
      // user closed dapp before triggering restore; resume to restore step
      show("restore");
      setStatus("restore-status", "Welcome back — your sweep is recorded. Restore is the next step.", "ok");
      enterRestoreStep();
      break;
    case "restore_sync_pending":
      show("verify");
      setStatus("verify-status", "Welcome back — verifying the restore…", "ok");
      enterVerifyStep();
      break;
    case "verified":
      show("verify");
      $("verify-success").hidden = false;
      $("verify-status").textContent = "(previous run — flow already complete)";
      break;
    default:
      show("welcome");
  }
}

// DOMContentLoaded promise — used by MDS.init to ensure event listeners are wired
// before any UI flow tries to render or respond to clicks.
const domReady = new Promise(resolve => {
  if (document.readyState !== "loading") resolve();
  else document.addEventListener("DOMContentLoaded", resolve);
});

domReady.then(() => {
  wireUp();
  detectPlatform();
});

// Probe this dapp's own permission level. If READ, show a neutral banner
// explaining that commands will queue in MiniHub Pending — but the dapp
// handles the pending case automatically via the sticky banner.
async function checkOwnPermission() {
  // The cleanest signal is `checkmode`, which returns "READ" or "WRITE"
  try {
    const r = await new Promise((res, rej) => {
      MDS.cmd("checkmode", x => x ? res(x) : rej(new Error("no response")));
    });
    const resp = r.response || {};
    const mode = resp.mode || resp.permission ||
      (typeof resp === "string" ? resp : "");
    return String(mode).toUpperCase();
  } catch (_e) {
    return "UNKNOWN";
  }
}

async function showWelcomePermissionWarning() {
  const banner = $("welcome-perm-warn");
  if (!banner) return;
  const mode = await checkOwnPermission();
  if (mode === "READ") {
    banner.hidden = false;
  } else {
    banner.hidden = true;
  }
}

MDS.init(async function (msg) {
  // Make sure wireUp() has run before any handler tries to address DOM elements
  await domReady;
  if (msg.event === "inited") {
    showTab("recover");
    showWelcomePermissionWarning();
    resumeFromPersisted();
  } else if (msg.event === "MINIMALOG") {
    onMinimaLog(msg.data);
  } else if (msg.event === "NEWBLOCK" || msg.event === "NEWBALANCE") {
    // Universal-Casino-style: a new block / balance change can be the signal that
    // a long-running pending command (like a send) has been confirmed. If we're
    // currently waiting on a pending send, treat this as a hint to re-poll.
    if (pendingState.uid && pendingState.uid !== "(unknown)" && !pendingState.isLongRunning) {
      checkPendingResolution();
    }
  }
});
