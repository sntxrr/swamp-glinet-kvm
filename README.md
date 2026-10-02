# swamp-glinet-kvm

A [swamp](https://swamp-club.com) extension repo for **GL.iNet KVMs** (Comet
GL-RM1 / GL-RM1PE), built with Deno's standard library plus the `curl` and
`openssl` binaries. It needs no vendor SDK.

## Extensions

### [`@sntxrr/glinet-kvm`](./extensions/models/glinet-kvm/README.md)

Health checks, screenshots, ATX power and virtual media for one KVM per model
instance.

| Method       | Writes?          | What it does                                                          |
| ------------ | ---------------- | --------------------------------------------------------------------- |
| `health`     | no               | Reachability, firmware currency, HDMI signal, HID, media, posture     |
| `screenshot` | no               | JPEG of the target's screen                                           |
| `atx`        | **with `apply`** | Power and reset buttons; refuses when no ATX board is attached        |
| `msd`        | **with `apply`** | Upload, download, attach, detach and remove virtual media             |

The firmware is a fork of PiKVM's `kvmd`, and three of its behaviours make a
naive client report the wrong thing. The factory TLS certificate expired in
1979. The video streamer sleeps until a viewer connects. And without the ATX
board, the API reports `power: "off"` for a running machine. The
[extension README](./extensions/models/glinet-kvm/README.md) covers each one,
and how this model handles it.

## Quick start

```bash
swamp extension pull @sntxrr/glinet-kvm
swamp model create @sntxrr/glinet-kvm kvm-a \
  --global-arg host=192.0.2.10 \
  --global-arg 'password=${{ vault.get(my-1password, "kvm-a/password") }}'
swamp model method run kvm-a health
swamp data get kvm-a health --json | jq '.content | {verdict, findings}'
```

## Layout

Model instances, vaults and workflows are site-specific, so they are
gitignored here. This repo is public; real instances live in a private repo.
