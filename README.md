# Herdr Remote Bridge

On-demand bridge for a machine that can open SSH connections to the Herdr VPS
but cannot receive SSH connections because it is only accessible through a web
terminal.

## Current V1

`prefix+alt+r` inspects the focused Herdr pane before creating a pending
connection:

- a local shell selects the local Mac as the listener host;
- an `ssh user@host` pane selects that SSH target as the listener host;
- the SSH target, port, jump host, source pane, session ID and token are written
to the pending state and passed to the waiting pane.

The V1 currently implements the context-aware listener selection and secure
session/token state. The SSH rendezvous transport is intentionally not enabled
yet: it must be provisioned on the selected host before accepting connections.
No clear-text TCP listener or public port is opened by this plugin.

## Planned connection flow

1. The action creates a pending session and token.
2. The remote browser terminal runs a short SSH bootstrap command.
3. The VPS validates the token through a forced-command bridge account.
4. The remote creates a loopback-only reverse forward to its local `sshd`.
5. The plugin opens a second Herdr pane through that forward.
6. The waiting pane remains the controller/status pane.

The SSH transport provides encryption. The token provides one-time session
binding and is not used as an encryption key.
