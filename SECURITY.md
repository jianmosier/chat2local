# Security boundaries

chat2local is an Alpha self-hosted file-access utility, not an independently audited remote-administration product. Do not expose its localhost control port directly to the Internet. Run a separate private instance for each owner.

## Authorization

The public MCP endpoint requires OAuth with S256 PKCE, registered callback validation and scope enforcement. Each computer has an independent device credential; the relay verifies that device before accepting its outbound transport. One reference grant resolves only devices and folders explicitly activated for that particular connection. Adding a device never copies an old computer's key. Ambiguous targets fail rather than selecting a different machine.

File operations require the intersection of token scopes, the connection's share list and the current native folder policy. `write_file` needs both OAuth `files:write` and explicit native direct-write permission. `propose_write` remains a reviewed proposal even for a directly writable root. New scope, new directory, or changed software version cannot silently supply consent.

The daily management API is NOT an MCP file tool. Its local endpoints require a per-process control secret, exact Host/Origin checks and bounded input. The native agent proves its own identity to the existing connection, prepares exact folder/mode snapshots, and activates them only after the user's persisted local confirmation. It cannot enroll other devices, mint OAuth tokens or authorize a different connection merely with its name. The interface's preparation step grants nothing; the one final consent covers the entire displayed batch.

New-device installation uses a separate owner-configured installation password and short-lived tickets with different native-claim and browser proofs. No default password is generated or published. The installer login cannot read existing shared files or replace operator credentials. Invitations are limited, expiring and device/session-bound; they do not contain the operator key.

## File and transport controls

The local service binds to 127.0.0.1, with bounded bodies, same-origin control APIs and no framing. Standard file operations reject path traversal, links/junctions, multiple hard links, sensitive filenames, non-UTF-8 or oversized content. Current limit is 64 KiB per text file. Hash matching, serial commits and backup-before-replacement protect against accidental overwrites. File tools do not provide deletion, command execution or drive-root access. The SEPARATELY authorized terminal tools below are not subject to the file-tool sandbox-like path checks once a command runs.

Revocation/pause are checked locally and on relevant server paths. Network reconnect does not replay file writes. Unknown write outcomes require reading back before retrying. Directory change journals resume the same decision, rather than granting a new scope after an uncertain response.

The owner of the HTTPS relay can see file contents in transit; this is not end-to-end encryption against that owner. File payloads are not deliberately persisted as cloud records, while OAuth metadata, permissions, hashes and bounded coordination state are. Do not enable payload logging on the public Worker.

## Explicit terminal execution

`terminal_execute/status/cancel` require a scoped connection with `terminal:execute`, a directly writable existing share, and a separately confirmed native terminal grant bound to that exact connection and root. Legacy grants and file-only OAuth tokens cannot execute. The scope is displayed during normal OAuth authorization; changing the local toggle cannot silently upgrade tokens. Old agents without terminal capability are not sent commands.

This is **not an OS sandbox**. Shell commands run as the desktop user and may access paths outside cwd, delete files, create detached descendants, and use the network. Only intended starting cwd, shell selection, input/output limits, credentials passed by the service, launch concurrency, and request identity are constrained. Use only with a trusted client and explicit task intent. Do not promise file-tool backups or filesystem confinement for shell side effects.

Reservations are durably stored before spawn. Reusing a request ID cannot launch a second process, including after network response loss. After agent restart, unfinished records are marked interrupted/unknown rather than replayed. Output is bounded; the private command journal can contain sensitive stdout/stderr and must not be published. Reaching the bounded journal capacity refuses new commands rather than deleting anti-replay evidence.

Cancellation/timeout requests attached process-tree termination; detached descendants may survive. Revoking a cloud token does not necessarily stop a previously running native command immediately. Cancellation does not roll back effects. The runtime environment passed to the shell is limited, but same-user commands can still read secrets available to that OS user. Local management denies silent terminal enabling; native test/CI simulations do not establish end-user consent.

## Installation and source releases

Public releases are built from an explicit source allowlist, with scanning for known deployment identifiers and credential-like strings. Private deployment config, operator vaults, device identities, internal handoff records, downloads and logs are excluded. This is an engineering guard, not a guarantee that an arbitrary edited file contains no secret.

Public bootstraps download fixed-version source archives and official Node archives over HTTPS and verify SHA-256 before execution. Checksums distributed by the same trusted host do not substitute for independent application signing or a compromised-publisher defense. Mac application signing/notarization and independent reproducible-build verification are not complete.

An update installs a separate version, refuses to stop unknown/busy local listeners, requests normal authenticated shutdown of the exact idle app, and verifies saved state is retained. It does not kill unrelated processes, change proxy settings, reset folder permissions or silently enable startup. If startup or verification fails, old program files and user data are retained for recovery; automatic rollback is not claimed.

## Remaining risks

Path checks are not an operating-system sandbox and cannot isolate same-user malware. Residual path-based races require further hardening. Windows stores sensitive app state with CurrentUser DPAPI; non-Windows storage currently relies on restrictive per-user file permissions rather than OS-backed encryption. Backups consume disk space and lack a complete retention/restore UI.

The supported MCP profile, provider adapter and browser tests do not certify every MCP client, operating system, corporate proxy or clean cloud account. Physical Windows and Mac access has been demonstrated for earlier releases; batch management and setup changes require their own acceptance. Whole-machine restart, unattended lifetime recovery and independent security review remain explicit release gates.

Report suspected vulnerabilities privately before disclosing working attack details. Never attach installation passwords, OAuth tokens, device keys, vault files or live deployment configuration to a public issue.
