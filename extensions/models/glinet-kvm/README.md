# @sntxrr/glinet-kvm

Operate a [GL.iNet KVM](https://www.gl-inet.com/products/gl-rm1/) (Comet
GL-RM1 / GL-RM1PE) from swamp: health checks, screenshots, ATX power and
virtual media.

Model type: `@sntxrr/glinet-kvm`

## Why this exists

GL.iNet's KVM firmware is a fork of PiKVM's `kvmd`, so its API is kvmd's,
plus GL.iNet's own firmware, 2FA and system endpoints. Three behaviours make a
naive client report the wrong thing:

**The TLS certificate cannot be validated.** The factory certificate is
self-signed, names `CN=localhost` with no SAN, and was minted while the device
clock read the Unix epoch, so it expired on 1979-12-30. Pinning it as a CA still
fails on expiry and hostname. Deno's `fetch` cannot skip verification per
request, so this model talks HTTP through `curl --insecure` and opens the viewer
websocket through `openssl s_client`. The password reaches both on **stdin**,
never argv, so it does not appear in a process listing. `health` reports the
certificate so the gap stays visible.

**The video streamer sleeps.** kvmd only runs the capture process while a
viewer is connected. With nobody watching, `/api/streamer/snapshot` answers 503
(even with `allow_offline=1`), which looks exactly like "no HDMI signal".
`screenshot` and `health` open a **receive-only** viewer session first. On the
devices this was built against, the streamer reported a source within a second.
No keyboard or mouse input is ever sent.

**ATX state is fabricated without the ATX board.** With no ATX add-on attached,
`/api/atx` still answers `power: "off"`, for a machine that is plainly running,
next to `enabled: false`. This model records the power state as `null`
(unknown) in that case, and refuses any button action, rather than reporting
success for a press wired to nothing.

## Methods

| Method       | Writes?           | What it does                                                         |
| ------------ | ----------------- | -------------------------------------------------------------------- |
| `health`     | no                | Reachability, auth, firmware, HDMI, HID, MSD, Tailscale, posture      |
| `screenshot` | no                | JPEG of the target's screen, stored as the `screenshot` file          |
| `atx`        | no                | Power state, or the plan for a button press                           |
| `atxPress`   | **always**        | Press power/reset; refuses without an ATX board                       |
| `msd`        | no                | Virtual media state, or the plan for a change                         |
| `msdChange`  | **always**        | Upload, download, attach, detach and remove virtual media             |

Reads and writes are separate methods (since 2026.10.19.1). `atx` and `msd`
record exactly which calls `atxPress` and `msdChange` would make with the same
arguments, and never change the device. Before that, `atx` and `msd` acted when
passed `apply: true`; they now **refuse** `apply: true` rather than ignoring it,
so a caller written for the old methods fails loudly instead of silently
becoming a dry run.

**Pre-flight checks.** The write methods run labeled `live` checks first,
scoped to them alone (swamp runs an unscoped check before every method):

| Check               | Method      | Fails when                               |
| ------------------- | ----------- | ---------------------------------------- |
| `atx-board-present` | `atxPress`  | No ATX board is attached                 |
| `atx-not-busy`      | `atxPress`  | An ATX operation is already in progress  |
| `msd-enabled`       | `msdChange` | Virtual media is disabled                |
| `msd-not-busy`      | `msdChange` | A virtual-media operation is in progress |

Checks of the same endpoint share one read, and a check that cannot read the
device fails rather than passes. The methods enforce the same conditions
themselves, so `--skip-check-label live` only skips the early answer, never
the guard. A refusal by a check leaves no `atx` or `msd` record (checks
cannot write data): the check's error is its only trace, and the latest record
still shows the previous outcome. Run `atx` or `msd` with the same arguments to
record the refusal as a plan. Refusals that depend on the arguments (image required, file
readable, image exists, drive function off) stay in the method: checks see
the arguments only unvalidated.

### `health`

Writes one `health` resource with a `verdict` of `ok`, `warn` or `fail` and a
list of `findings`. An unreachable device or a rejected password is recorded as
`fail`, not thrown, so a scheduled check always leaves a record to alert on.

| Finding                     | Severity           | Meaning                                                      |
| --------------------------- | ------------------ | ------------------------------------------------------------ |
| `unreachable`, `auth_failed` | fail              | Could not talk to kvmd, or it rejected the credentials       |
| `api_error`                 | fail               | Authenticated, then a core endpoint failed                   |
| `firmware_update_available` | warn               | The device reports a newer GL.iNet release                   |
| `no_video_signal`           | warn               | The streamer woke, and the target is sending no video        |
| `hid_offline`               | warn               | The target has not enumerated the USB keyboard/mouse         |
| `virtual_media_attached`    | warn               | An image is attached, and the next reboot may boot from it   |
| `storage_partition_attached` | warn              | GL.iNet's own storage partition is exposed to the target     |
| `viewer_failed`             | warn               | No viewer session could be opened, so video went unchecked   |
| `virtual_media_not_presented` | info             | Attached per kvmd, but the USB mass-storage function is off  |
| `clock_skew`                | warn               | The device clock is off by more than `maxClockSkewSeconds`   |
| `two_factor_disabled`       | info (warn strict) | Web UI 2FA is off                                            |
| `webterm_enabled`           | info (warn strict) | The browser web terminal (a root shell) is on                |
| `tls_untrusted`             | info (warn strict) | Self-signed, expired, or not naming the host                 |
| `atx_absent`                | info               | No ATX board, so power state and control are unavailable     |
| `tailscale_unreachable`     | warn               | With `tailnetIp`: nothing answered on that address           |
| `tailscale_wrong_device`    | warn               | With `tailnetIp`: something other than this KVM answered     |
| `tailscale_ip_changed`      | warn               | With `tailnetIp`: the device reports a different tailnet IP  |
| `tailscale_not_running`     | warn               | Tailscale is enabled, but tailscaled is not running          |
| `tailscale_not_connected`   | warn               | tailscaled is in a state other than `Running` (e.g. logged out) |
| `tailscale_disabled`        | info (warn with `tailnetIp`) | Tailscale is turned off on the device              |

Posture findings are `info` by default because every factory-fresh device has
them. Pass `strictSecurity: true` to make them count toward the verdict.

**Tailscale.** `health` reads GL.iNet's `GET /api/tailscale/config`, `/status`
and `/login_status`. A 404 means the firmware has no Tailscale API; any other
failure is logged. It never calls `GET /api/tailscale/login`, which is not
read-only: it starts a login. `tailscale` is null only when the device could not
be read, or when it has no Tailscale API **and** no `tailnetIp` is set; with
`tailnetIp` set the object is always present and its device fields may be null.

The device's own view is not enough: a node deleted from the tailnet keeps
reporting `Running`, because the device cannot tell its node is gone. Set the
`tailnetIp` global argument to have `health` also probe that address from the
tailnet node swamp runs behind. The probe is **anonymous**, and its transport is
built without credentials: it matters most when the pinned address is stale,
and then whatever answers there is not this KVM. Identity is proved without a
password instead: kvmd answers an anonymous `GET /api/auth/check` with its own
`401 {"ok": false}` envelope, and each device has its own TLS certificate, so
the certificate on the tailnet address must match the one on `host`.
`tailscale_unreachable` means nothing answered; `tailscale_wrong_device` means
something else did. A re-added node gets a new address, so
`tailscale_ip_changed` names both and the fix is updating `tailnetIp`.

All HTTP goes through `curl -q` with `noproxy = "*"`: `-q` keeps a user's
`~/.curlrc` (a `verbose` there would print the password header into errors) out
of it, and the KVM is always reached directly, never through a proxy that would
see the credentials over unverified TLS.

Arguments: `checkVideo` (default `true`), `checkFirmware` (default `true`; the
device asks GL.iNet's servers, and a failure there is logged, not counted),
`strictSecurity` (default `false`), `maxClockSkewSeconds` (default `300`).

### `screenshot`

Stores the frame as the `screenshot` file (`image/jpeg`) and a
`screenshotMeta` resource with the resolution, size and wait time. With no HDMI
signal it records `signal: false` and then fails, so the run reads red.

`ocr: true` asks kvmd to OCR the frame too. Firmware V1.9.1 answers that with
HTTP 500, so it is logged as unavailable and the screenshot still succeeds.

```bash
swamp model method run kvm-a screenshot
swamp data get kvm-a screenshot --json | jq -r .contentPath
```

### `atx` and `atxPress`

`action` is one of `status` (default;
`atx` only), `on`, `off`, `off_hard`, `reset_hard`,
`click_power`, `click_power_long`, `click_reset`. `on` and `off` are kvmd's
"soft" actions: they press power only if the state differs. The `click_*`
actions press regardless.

The button-press path follows upstream kvmd's API and is covered by tests
against a scripted kvmd, but it has **not** been exercised on hardware: none of
the devices this was built against has an ATX board. Status reads and the
no-board refusal have been verified live.

```bash
swamp model method run kvm-a atx --input action=reset_hard        # the plan; presses nothing
swamp model method run kvm-a atxPress --input action=reset_hard
```

### `msd` and `msdChange`

`msd` takes every action and records the plan; `msdChange` takes every action
but `status` and makes the calls.

| `action`     | Needs               | Device calls                                               |
| ------------ | ------------------- | ---------------------------------------------------------- |
| `status`     |                     | none                                                       |
| `upload`     | `image`, `file`     | `POST /api/msd/write` streaming the local file             |
| `download`   | `image`, `url`      | `POST /api/msd/write_remote`: the KVM fetches the URL itself |
| `connect`    | `image`, `cdrom`    | `set_params`, then `set_connected?connected=1`             |
| `disconnect` |                     | `set_connected?connected=0`                                |
| `remove`     | `image`             | `POST /api/msd/remove`                                     |

**An attach can be invisible to the target.** GL.iNet's USB gadget presents a
CD-ROM or flash drive only when that function is enabled in the KVM's USB
device settings (`start_cdrom` / `start_flash`, both off from the factory).
With it off, kvmd still accepts the attach and reports `connected: true`, while
the target enumerates nothing but the keyboard/mouse device. `connect` reads
the gadget configuration and refuses in that case, and `health` reports such
media as `virtual_media_not_presented` (info) rather than as attached. With the
function on, an attached image appeared on a Proxmox target as a USB optical
drive carrying the ISO's volume label. Turning the function on or off
re-enumerates the KVM's USB device, so the target's KVM keyboard and mouse drop
for a moment.

The model refuses before calling anything when the image is missing, already
exists, will not fit, is attached (for `remove`), or another image is already
attached (for `connect`). `download` is the better choice for a large ISO over a
slow link, because the bytes never pass through the machine running swamp.

## Setup

```yaml
# models/@sntxrr/glinet-kvm/kvm-a.yaml
type: "@sntxrr/glinet-kvm"
name: kvm-a
globalArguments:
  host: 192.0.2.10          # prefer the LAN IP
  password: ${{ vault.get(my-1password, "kvm-a/password") }}
  tailnetIp: 198.51.100.7   # optional: probe the Tailscale path too
```

Use the device's **IP address** when swamp runs in a container. A short name can
be completed by the container's DNS search domain and land on a reverse proxy,
which answers 404 to everything and looks like a broken KVM.

Requirements on the machine running swamp: `curl` and `openssl` on `PATH`. Both
the stock macOS and Debian builds work; `curl` does not need websocket support.

Two-factor authentication is not supported: kvmd expects the TOTP code appended
to the password on every request. Leave 2FA off for the account this model uses,
or don't use this model.

## Scheduling

`health` is cheap: about seventeen GET requests, a viewer session of a second or
two, and with `tailnetIp` one anonymous GET and a TLS handshake on that address. Hourly is reasonable. Alert on `verdict != "ok"` and on the age of the
latest `health` record, so a check that stops running is noticed too.

## Development

```bash
~/.swamp/deno/deno check glinet_kvm.ts
~/.swamp/deno/deno test --allow-read --allow-env --allow-write \
  --allow-net=127.0.0.1 --allow-run=curl,openssl glinet_kvm_test.ts
```

The tests run against a scripted fake of kvmd through `transportFactory`, and
assert what the model does **not** send as well as what it does. Every write
test checks the POST log.
