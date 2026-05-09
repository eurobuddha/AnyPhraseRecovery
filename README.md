# AnyPhraseRecovery

A Minima MiniDapp that helps users of compromised web-wallets sweep their funds out
to safety **without giving up control of the host Minima node**.

## Why this exists

The "Web Wallet" hosted at `wallet.minima.global` (and any node serving the same
MiniDapp via `publicmds`) sends the user's seed phrase and private keys in cleartext
to the hosting node as part of MDS command strings:

```js
// from the audited webWallet 2.5.2 bundle
window.MDS.cmd('keys action:genkey phrase:"' + V + '"', ...)
window.MDS.cmd('sendfrom fromaddress:' + l + ' ... privatekey:' + t + ' ...', ...)
```

When that MiniDapp runs on the user's own local node, this is fine — the bridge is
loopback and the keys never leave the device. When the same code is *served publicly*
to users who don't run a node, every seed and private key transits to the hosting
node operator's machine in the request body. From there it's in the Java process
memory, in any access logs, in any application logs, and visible to anyone with
shell access to that host. Multiple wallets have been drained with this pattern —
single-tx sweeps with no change output, signed by many different private keys, days
to weeks after the user's last legitimate webwallet activity.

## What the dapp does

```
1. SNAPSHOT ─ run `backup file:<rand>.bak password:<rand>` to produce an encrypted
              snapshot of the host node. Works on password-locked vaults too —
              the .bak inherits the lock state. The dapp does NOT read or display
              your seed at any point.
2. POSSESS  ─ run megammrsync(action:resync, phrase:"<compromised seed>") to
              import the compromised wallet onto the host node.
              (The node restarts.)
3. SWEEP    ─ send all recovered balances to the host node's own existing address.
4. RESTORE  ─ run megammrsync(action:resync, file:<backup>, password:<password>)
              to bring the host node back to its original seed and chain state.
              (The node restarts again.)
5. VERIFY   ─ confirm the original wallet identity is back; the recovered funds
              are now sitting at the user's normal address.
```

The compromised seed never leaves the device — it goes only to the user's local
MDS bridge, never to a remote server. The host node's own seed is never read by
the dapp; the user is responsible for having an independent off-device backup of
their existing seed (paper, hardware wallet, separate device) in case both the
.bak path AND the dapp's restore step fail.

## Install

Download `AnyPhraseRecovery-X.Y.Z.mds.zip` from the [releases page](../../releases)
or directly from the root of this repo, then on a Minima node you control:

- **From MiniHub UI:** click `Install MiniDapp` and select the zip.
- **From terminal:** `mds action:install file:AnyPhraseRecovery-0.3.0.mds.zip`

The dapp shows up as **AnyPhraseRecovery**.

## Usage

1. Install on the **same Minima node** you want the recovered funds to end up on.
2. Open the dapp.
3. Step 1 — write down both your existing node's seed AND the random backup password
   the dapp generates. **On paper. Not on the device.**
4. Step 2 — paste the compromised webWallet seed.
5. Step 3 — pick a megammr host (defaults to a random one of four; advanced lets
   you supply a custom one).
6. **Restart Minima** when the dapp tells you to. On Android: kill from the app
   switcher and reopen from the home screen. On desktop: stop and re-launch the
   `java -jar` process.
7. The dapp resumes automatically when you reopen it. Confirm the recovered
   balance and click Send.
8. Wait ~60 seconds for the chain to mine your sweep, then click Restore.
9. **Restart Minima again** when prompted.
10. The dapp re-opens to the verification screen. Three checks confirm your wallet
    identity is back and your funds landed correctly.

## Why the two restarts are required

`megammrsync action:resync` is a destructive seed-replacement operation. Until the
node is restarted, subsequent commands return empty bodies (the wallet subsystem
needs to reinitialize). This is a hard constraint of the current Minima node, not
a limitation of the dapp.

The dapp persists the state it needs to resume (host, backup file path, backup
password, destination Mx, expected wallet fingerprint) into `localStorage` BEFORE
each `megammrsync`, then resumes at the right step when you reopen the dapp after
the restart. Nothing the attacker would care about — specifically, neither the
host's seed nor the compromised seed — is persisted.

## Failure modes

If anything goes wrong, the user holds **two independent paths** back to their
original wallet:

1. **The encrypted .bak file**. The dapp shows the absolute path; the user wrote
   the password down on paper. From the terminal:
   ```
   megammrsync action:resync host:<host> file:<backup-path> password:<password>
   ```
   then restart.

2. **The original seed phrase on paper** (written down in step 1 and verified by
   typing-back the words). Reinstall Minima fresh and run:
   ```
   vault action:restorekeys phrase:"<your original seed>"
   ```
   then restart.

The recovered funds are on chain at the destination address regardless of how the
host wallet is restored. They're spendable as soon as the wallet is back.

## Limitations

- Only works for funds at addresses the chosen megammr host has indexed. If a
  fresh megammr doesn't yet contain coins for the compromised seed, try a
  different host.
- The wait between sweep and restore is currently a fixed 60-second countdown.
  If the chain happens to be unusually slow at the time of recovery, the megammr
  might not have indexed the swept transaction yet — in which case run a manual
  follow-up `megammrsync` against the host wallet after restore.
- Only supports the default-wallet (single-key SIGNEDBY) script pattern. Custom
  script-locked coins won't be visible.
- USDT and other atomic-swap-only tokens were never at risk from the webwallet
  vulnerability (they don't use the `sendfrom` path) — this dapp only sweeps
  whatever the megammr reports at the imported wallet.

## Architecture

| File          | Role                                                   |
|---------------|--------------------------------------------------------|
| `dapp.conf`   | MiniDapp metadata: name, version, icon                 |
| `index.html`  | Two-tab UI shell: Recover funds, Become a MegaMMR host |
| `app.js`      | All flow logic, persistent state machine               |
| `styles.css`  | Mobile-first dark theme                                |
| `mds.js`      | Standard Minima MDS bridge (unmodified)                |
| `favicon.svg` | Icon                                                   |

No build step. Plain HTML + JS. Audit the source directly before installing.

## License

MIT — see [LICENSE](LICENSE).

## Status

Validated end-to-end against a Minima v1.0.48.3 node running real funds (sweep of a
real webWallet seed succeeded; host wallet restored to byte-identical state). No
warranty implied — anyone using this is encouraged to read the source and test on
a throwaway node first.
