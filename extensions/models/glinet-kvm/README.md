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
| `health`     | no                | Reachability, auth, firmware currency, HDMI signal, HID, MSD, posture |
| `screenshot` | no                | JPEG of the target's screen, stored as the `screenshot` file          |
| `atx`        | **with `apply`**  | Power state, or power/reset buttons; refuses without an ATX board     |
| `msd`        | **with `apply`**  | List, upload, download, attach, detach and remove virtual media       |

Every method that can change the device is a **dry run unless `apply: true`**.
The dry run records exactly which calls it would make.

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
| `clock_skew`                | warn               | The device clock is off by more than `maxClockSkewSeconds`   |
| `two_factor_disabled`       | info (warn strict) | Web UI 2FA is off                                            |
| `webterm_enabled`           | info (warn strict) | The browser web terminal (a root shell) is on                |
| `tls_untrusted`             | info (warn strict) | Self-signed, expired, or not naming the host                 |
| `atx_absent`                | info               | No ATX board, so power state and control are unavailable     |

Posture findings are `info` by default because every factory-fresh device has
them. Pass `strictSecurity: true` to make them count toward the verdict.

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

### `atx`

`action` is one of `status` (default), `on`, `off`, `off_hard`, `reset_hard`,
`click_power`, `click_power_long`, `click_reset`. `on` and `off` are kvmd's
"soft" actions: they press power only if the state differs. The `click_*`
actions press regardless.

The button-press path follows upstream kvmd's API and is covered by tests
against a scripted kvmd, but it has **not** been exercised on hardware: none of
the devices this was built against has an ATX board. Status reads and the
no-board refusal have been verified live.

```bash
swamp model method run kvm-a atx --input action=reset_hard              # dry run
swamp model method run kvm-a atx --input action=reset_hard --input apply=true
```

### `msd`

| `action`     | Needs               | Device calls                                               |
| ------------ | ------------------- | ---------------------------------------------------------- |
| `status`     |                     | none                                                       |
| `upload`     | `image`, `file`     | `POST /api/msd/write` streaming the local file             |
| `download`   | `image`, `url`      | `POST /api/msd/write_remote`: the KVM fetches the URL itself |
| `connect`    | `image`, `cdrom`    | `set_params`, then `set_connected?connected=1`             |
| `disconnect` |                     | `set_connected?connected=0`                                |
| `remove`     | `image`             | `POST /api/msd/remove`                                     |

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

`health` is cheap: about ten GET requests and a viewer session of a second or
two. Hourly is reasonable. Alert on `verdict != "ok"` and on the age of the
latest `health` record, so a check that stops running is noticed too.

## Development

```bash
~/.swamp/deno/deno check glinet_kvm.ts
~/.swamp/deno/deno test --allow-read --allow-env --allow-write glinet_kvm_test.ts
```

The tests run against a scripted fake of kvmd through `transportFactory`, and
assert what the model does **not** send as well as what it does. Every write
test checks the POST log.
