/**
 * Operate a GL.iNet KVM (Comet GL-RM1 / GL-RM1PE family) from swamp.
 *
 * GL.iNet's KVM firmware is a fork of PiKVM's `kvmd`. It speaks kvmd's HTTP API
 * — `{"ok": bool, "result": ...}` envelopes, `X-KVMD-User` / `X-KVMD-Passwd`
 * header auth — with GL.iNet's own endpoints (firmware upgrade, 2FA, system)
 * layered on top. This model wraps both.
 *
 * ## Three things about these devices that shape the code
 *
 * **The TLS certificate cannot be validated.** The factory certificate is
 * self-signed, names `CN=localhost` with no SAN, and was minted while the
 * device clock read the Unix epoch, so it expired in 1979. Pinning it as a CA
 * still fails on expiry and on hostname. Deno's `fetch` has no per-request
 * "skip verification" switch, so HTTP goes through `curl --insecure` and the
 * viewer websocket through `openssl s_client`. Credentials are handed to both
 * on **stdin**, never argv, so they do not appear in a process listing.
 * `health` reports the certificate state so the gap stays visible.
 *
 * **The video streamer sleeps.** kvmd runs the capture process only while a
 * viewer is connected. With nobody watching, `/api/streamer/snapshot` answers
 * 503 — even with `allow_offline=1` — which is indistinguishable from "no
 * HDMI signal" unless you wake it. `screenshot` (and `health` with
 * `checkVideo`) open a receive-only viewer session first. It never sends
 * keyboard or mouse input.
 *
 * **ATX state is fabricated when there is no ATX board.** Without GL.iNet's ATX
 * add-on, `/api/atx` still answers `power: "off"` — for a machine that is
 * plainly running — alongside `enabled: false`. This model never reports that
 * `off` as a power state, and refuses to "press" a button that is not wired to
 * anything rather than reporting success for a no-op.
 *
 * Every method that changes device state defaults to a dry run; pass
 * `apply: true` to act.
 *
 * @module
 */

import { z } from "npm:zod@4";

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

/** Header values travel in a raw HTTP request; a CR or LF would inject headers. */
const NO_CRLF = /^[^\r\n]*$/;

const GlobalArgsSchema = z.object({
  host: z.string().min(1).describe(
    "Address of the KVM: a LAN IP or a hostname that resolves from wherever " +
      "swamp runs. Prefer the IP — inside a container a short name can be " +
      "completed by a search domain and land on a reverse proxy instead.",
  ),
  port: z.number().int().min(1).max(65535).default(443).describe(
    "HTTPS port of the KVM web UI.",
  ),
  username: z.string().min(1).regex(NO_CRLF).default("admin").describe(
    "Web UI user. GL.iNet KVMs ship with a single `admin` account.",
  ),
  // `.meta({ sensitive: true })` sits on the declaration line: the push-time
  // safety analyzer reads that line, so a marker after a multi-line describe()
  // would be invisible to it.
  password: z.string().min(1).regex(NO_CRLF).meta({ sensitive: true })
    .describe(
      "Web UI password. Supply a vault reference, never a literal. If two-" +
        "factor auth is enabled on the device this model cannot log in.",
    ),
  timeoutMs: z.number().int().positive().default(15000).describe(
    "Per-request timeout for API calls (uploads and downloads take their own).",
  ),
});

/** Validated global arguments for one KVM. */
export type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/** Raw HTTP response from the KVM. */
export interface HttpResult {
  status: number;
  contentType: string;
  body: Uint8Array;
}

/** Options for a single API request. */
export interface RequestOptions {
  query?: Record<string, string>;
  /** Local file streamed as the request body (MSD upload). */
  uploadFile?: string;
  timeoutMs?: number;
}

/** Peer certificate facts, as far as `openssl` can tell. */
export interface CertInfo {
  subject: string;
  issuer: string;
  notAfter: string | null;
  sans: string[];
}

/** A live viewer session that keeps the streamer awake until closed. */
export interface Viewer {
  close(): Promise<void>;
}

/** Everything the model needs from the network, injectable for tests. */
export interface Transport {
  request(
    method: "GET" | "POST",
    path: string,
    opts?: RequestOptions,
  ): Promise<HttpResult>;
  openViewer(): Promise<Viewer>;
  peerCertificate(): Promise<CertInfo | null>;
}

/** Quote a value for a curl config file (`-K`). */
export function curlQuote(value: string): string {
  return '"' +
    value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\r/g, "\\r")
      .replace(/\n/g, "\\n").replace(/\t/g, "\\t") +
    '"';
}

/** True when `host` is a literal IPv4 or IPv6 address. */
export function isIpLiteral(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":");
}

/** Build `https://host:port/path?query`. */
export function buildUrl(
  g: Pick<GlobalArgs, "host" | "port">,
  path: string,
  query: Record<string, string> = {},
): string {
  const host = g.host.includes(":") ? `[${g.host}]` : g.host;
  const qs = new URLSearchParams(query).toString();
  return `https://${host}:${g.port}${path}${qs ? `?${qs}` : ""}`;
}

/**
 * Render the curl config for one request. Pure and exported so the quoting —
 * the only thing standing between a password containing `"` and a broken
 * header — is testable without a device.
 */
export function curlConfig(
  g: GlobalArgs,
  method: "GET" | "POST",
  path: string,
  outFile: string,
  opts: RequestOptions = {},
): string {
  const lines = [
    `url = ${curlQuote(buildUrl(g, path, opts.query))}`,
    // The factory certificate is self-signed, CN=localhost, expired in 1979.
    "insecure",
    "silent",
    "show-error",
    `request = ${curlQuote(method)}`,
    `max-time = ${Math.ceil((opts.timeoutMs ?? g.timeoutMs) / 1000)}`,
    `connect-timeout = 10`,
    `header = ${curlQuote(`X-KVMD-User: ${g.username}`)}`,
    `header = ${curlQuote(`X-KVMD-Passwd: ${g.password}`)}`,
    `output = ${curlQuote(outFile)}`,
    `write-out = ${curlQuote("%{http_code}\\t%{content_type}")}`,
  ];
  if (opts.uploadFile) {
    lines.push(
      `header = ${curlQuote("Content-Type: application/octet-stream")}`,
    );
    lines.push(`data-binary = ${curlQuote(`@${opts.uploadFile}`)}`);
  } else if (method === "POST") {
    // kvmd's POST handlers take their arguments in the query string; send an
    // explicit empty body so curl does not wait on stdin or omit the length.
    lines.push(`data = ""`);
  }
  return lines.join("\n") + "\n";
}

/** The websocket upgrade request a browser would send to `/api/ws`. */
export function viewerHandshake(g: GlobalArgs, key: string): string {
  return [
    "GET /api/ws?stream=1 HTTP/1.1",
    `Host: ${g.host}`,
    "Upgrade: websocket",
    "Connection: Upgrade",
    `Sec-WebSocket-Key: ${key}`,
    "Sec-WebSocket-Version: 13",
    `X-KVMD-User: ${g.username}`,
    `X-KVMD-Passwd: ${g.password}`,
    "",
    "",
  ].join("\r\n");
}

/** Parse the `openssl x509 -text` dump into the fields `health` reports. */
export function parseCertText(text: string): CertInfo {
  const line = (re: RegExp): string => (text.match(re)?.[1] ?? "").trim();
  const sanBlock = text.match(
    /X509v3 Subject Alternative Name:[^\n]*\n\s*([^\n]+)/,
  )?.[1] ?? "";
  const sans = sanBlock.split(",").map((s) => s.trim()).filter(Boolean)
    .map((s) => s.replace(/^(DNS|IP Address):/, ""));
  const notAfterRaw = line(/Not After\s*:\s*([^\n]+)/);
  const parsed = notAfterRaw ? Date.parse(notAfterRaw) : NaN;
  return {
    subject: line(/Subject:\s*([^\n]+)/),
    issuer: line(/Issuer:\s*([^\n]+)/),
    notAfter: Number.isNaN(parsed) ? null : new Date(parsed).toISOString(),
    sans,
  };
}

async function runCommand(
  cmd: string,
  args: string[],
  stdin: string,
  timeoutMs: number,
): Promise<{ code: number; stdout: Uint8Array; stderr: string }> {
  const child = new Deno.Command(cmd, {
    args,
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  const timer = setTimeout(() => {
    try {
      child.kill("SIGKILL");
    } catch { /* already exited */ }
  }, timeoutMs);
  try {
    const w = child.stdin.getWriter();
    await w.write(new TextEncoder().encode(stdin));
    await w.close();
    const out = await child.output();
    return {
      code: out.code,
      stdout: out.stdout,
      stderr: new TextDecoder().decode(out.stderr),
    };
  } finally {
    clearTimeout(timer);
  }
}

/** Default transport: `curl` for HTTP, `openssl s_client` for the viewer. */
export class CliTransport implements Transport {
  constructor(private readonly g: GlobalArgs) {}

  /** Issue one API request through curl, credentials on stdin. */
  async request(
    method: "GET" | "POST",
    path: string,
    opts: RequestOptions = {},
  ): Promise<HttpResult> {
    const outFile = await Deno.makeTempFile({ prefix: "glinet-kvm-" });
    try {
      const timeoutMs = opts.timeoutMs ?? this.g.timeoutMs;
      const res = await runCommand(
        "curl",
        ["-K", "-"],
        curlConfig(this.g, method, path, outFile, opts),
        timeoutMs + 5000,
      );
      if (res.code !== 0) {
        // curl's stderr names the failure (refused, timeout, DNS) and never
        // echoes the config it read, so it is safe to surface.
        throw new Error(
          `${method} ${path} on ${this.g.host} failed (curl exit ${res.code}): ${res.stderr.trim()}`,
        );
      }
      const [code, contentType = ""] = new TextDecoder().decode(res.stdout)
        .split("\t");
      return {
        status: Number(code),
        contentType,
        body: await Deno.readFile(outFile),
      };
    } finally {
      await Deno.remove(outFile).catch(() => {});
    }
  }

  /** Open a receive-only websocket session so kvmd starts the streamer. */
  async openViewer(): Promise<Viewer> {
    const args = [
      "s_client",
      "-quiet",
      "-connect",
      `${this.g.host}:${this.g.port}`,
    ];
    if (!isIpLiteral(this.g.host)) args.push("-servername", this.g.host);
    const child = new Deno.Command("openssl", {
      args,
      stdin: "piped",
      stdout: "piped",
      stderr: "null",
    }).spawn();
    const close = async (): Promise<void> => {
      try {
        child.kill("SIGTERM");
      } catch { /* already exited */ }
      await child.status.catch(() => {});
    };

    const key = btoa(
      String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))),
    );
    const writer = child.stdin.getWriter();
    await writer.write(new TextEncoder().encode(viewerHandshake(this.g, key)));
    // stdin stays open: closing it would end the TLS session.

    const reader = child.stdout.getReader();
    let head = "";
    // A device that accepts TCP and never answers would leave read() pending
    // forever; killing openssl at the deadline ends it, so a scheduled run
    // cannot hang here.
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        child.kill("SIGKILL");
      } catch { /* already exited */ }
    }, this.g.timeoutMs);
    try {
      while (!head.includes("\r\n\r\n")) {
        const { value, done } = await reader.read();
        if (done) {
          throw new Error(
            timedOut
              ? `viewer handshake on ${this.g.host} timed out after ${this.g.timeoutMs}ms`
              : `viewer connection to ${this.g.host} closed during handshake`,
          );
        }
        head += new TextDecoder().decode(value);
      }
    } catch (e) {
      await close();
      throw e;
    } finally {
      clearTimeout(timer);
    }
    const status = head.split("\r\n")[0];
    if (!/ 101 /.test(status)) {
      await close();
      throw new Error(
        `viewer websocket refused on ${this.g.host}: ${status}` +
          (/ 40[13] /.test(status) ? " (check username/password)" : ""),
      );
    }
    // Drain kvmd's event frames so the pipe never fills and stalls the server.
    (async () => {
      try {
        while (!(await reader.read()).done) { /* discard */ }
      } catch { /* closed */ }
    })();
    return {
      close: async () => {
        await writer.close().catch(() => {});
        await close();
      },
    };
  }

  /** Read the peer certificate with openssl; null if openssl cannot. */
  async peerCertificate(): Promise<CertInfo | null> {
    const args = ["s_client", "-connect", `${this.g.host}:${this.g.port}`];
    if (!isIpLiteral(this.g.host)) args.push("-servername", this.g.host);
    const hello = await runCommand("openssl", args, "", this.g.timeoutMs);
    const pem = new TextDecoder().decode(hello.stdout).match(
      /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/,
    )?.[0];
    if (!pem) return null;
    const dump = await runCommand(
      "openssl",
      ["x509", "-noout", "-text"],
      pem + "\n",
      this.g.timeoutMs,
    );
    if (dump.code !== 0) return null;
    return parseCertText(new TextDecoder().decode(dump.stdout));
  }
}

/**
 * Seam for tests: swap `create` to inject a fake transport. Production code
 * never touches this.
 */
export const transportFactory = {
  create: (g: GlobalArgs): Transport => new CliTransport(g),
};

// ---------------------------------------------------------------------------
// kvmd envelope
// ---------------------------------------------------------------------------

/**
 * Unwrap kvmd's `{ok, result}` envelope. Throws with kvmd's own error name
 * and message, which are far more useful than the bare HTTP status.
 */
export function unwrap(path: string, res: HttpResult): unknown {
  const text = new TextDecoder().decode(res.body);
  let parsed: { ok?: boolean; result?: unknown } | null = null;
  try {
    parsed = JSON.parse(text);
  } catch { /* not JSON */ }
  if (parsed && typeof parsed === "object" && "ok" in parsed) {
    if (parsed.ok) return parsed.result;
    const r = (parsed.result ?? {}) as { error?: string; error_msg?: string };
    throw new Error(
      `${path}: HTTP ${res.status} ${r.error ?? "error"}: ${r.error_msg ?? ""}`
        .trim(),
    );
  }
  throw new Error(
    `${path}: HTTP ${res.status}, not a kvmd response: ${text.slice(0, 120)}`,
  );
}

async function getJson(
  t: Transport,
  path: string,
  query?: Record<string, string>,
): Promise<unknown> {
  return unwrap(path, await t.request("GET", path, { query }));
}

async function postJson(
  t: Transport,
  path: string,
  query: Record<string, string>,
  opts: RequestOptions = {},
): Promise<unknown> {
  return unwrap(path, await t.request("POST", path, { ...opts, query }));
}

// deno-lint-ignore no-explicit-any
type Json = any;

// ---------------------------------------------------------------------------
// Health evaluation (pure)
// ---------------------------------------------------------------------------

const FindingSchema = z.object({
  severity: z.enum(["info", "warn", "fail"]),
  code: z.string(),
  message: z.string(),
});

/** One observation from `health`. Only `warn` and `fail` affect the verdict. */
export type Finding = z.infer<typeof FindingSchema>;

/** The device facts `evaluateHealth` judges. */
export interface HealthFacts {
  host: string;
  checkedAt: Date;
  firmware: string | null;
  latestFirmware: string | null;
  deviceTime: number | null;
  atxEnabled: boolean;
  msdConnected: boolean;
  msdImage: string | null;
  partitionConnected: boolean;
  hidOnline: boolean | null;
  twoFactorEnabled: boolean | null;
  webtermEnabled: boolean;
  video: { checked: boolean; online: boolean | null };
  viewerError: string | null;
  cert: CertInfo | null;
  strictSecurity: boolean;
  maxClockSkewSeconds: number;
}

/** True when the certificate names `host` in a SAN, or in its CN when SAN-less. */
export function certMatchesHost(cert: CertInfo, host: string): boolean {
  if (cert.sans.length) return cert.sans.includes(host);
  return new RegExp(
    `CN\\s*=\\s*${host.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(,|$)`,
  )
    .test(cert.subject);
}

/** Turn device facts into findings and a verdict. Pure and exported for tests. */
export function evaluateHealth(f: HealthFacts): {
  findings: Finding[];
  verdict: "ok" | "warn" | "fail";
} {
  const findings: Finding[] = [];
  const security = f.strictSecurity ? "warn" : "info";

  if (f.firmware && f.latestFirmware && f.firmware !== f.latestFirmware) {
    findings.push({
      severity: "warn",
      code: "firmware_update_available",
      message:
        `firmware ${f.firmware} is installed; ${f.latestFirmware} is available`,
    });
  }
  if (f.video.checked && f.video.online === false) {
    findings.push({
      severity: "warn",
      code: "no_video_signal",
      message: "the streamer woke but reports no HDMI signal from the target",
    });
  }
  if (f.hidOnline === false) {
    findings.push({
      severity: "warn",
      code: "hid_offline",
      message:
        "USB HID is not enumerated by the target; keyboard and mouse will not work",
    });
  }
  if (f.msdConnected) {
    // A forgotten ISO is a boot-order landmine: the next reboot may boot it.
    findings.push({
      severity: "warn",
      code: "virtual_media_attached",
      message: `virtual media is attached to the target${
        f.msdImage ? ` (${f.msdImage})` : ""
      }`,
    });
  }
  if (f.partitionConnected) {
    findings.push({
      severity: "warn",
      code: "storage_partition_attached",
      message:
        "the KVM's storage partition is attached to the target as a USB drive",
    });
  }
  if (f.viewerError) {
    findings.push({
      severity: "warn",
      code: "viewer_failed",
      message:
        `could not open a viewer session to test video: ${f.viewerError}`,
    });
  }
  if (f.deviceTime !== null) {
    const skew = Math.abs(f.deviceTime - f.checkedAt.getTime() / 1000);
    if (skew > f.maxClockSkewSeconds) {
      findings.push({
        severity: "warn",
        code: "clock_skew",
        message: `device clock is ${Math.round(skew)}s off`,
      });
    }
  }
  if (!f.atxEnabled) {
    findings.push({
      severity: "info",
      code: "atx_absent",
      message:
        "no ATX board: power state is unknown and power control is unavailable",
    });
  }
  if (f.twoFactorEnabled === false) {
    findings.push({
      severity: security,
      code: "two_factor_disabled",
      message: "web UI two-factor authentication is off",
    });
  }
  if (f.webtermEnabled) {
    findings.push({
      severity: security,
      code: "webterm_enabled",
      message: "the browser web terminal (a root shell) is enabled",
    });
  }
  if (f.cert) {
    const problems: string[] = [];
    if (f.cert.subject === f.cert.issuer) problems.push("self-signed");
    if (
      f.cert.notAfter && Date.parse(f.cert.notAfter) < f.checkedAt.getTime()
    ) {
      problems.push(`expired ${f.cert.notAfter.slice(0, 10)}`);
    }
    if (!certMatchesHost(f.cert, f.host)) {
      problems.push(`does not name ${f.host}`);
    }
    if (problems.length) {
      findings.push({
        severity: security,
        code: "tls_untrusted",
        message: `TLS certificate is ${problems.join(", ")}`,
      });
    }
  }

  const verdict = findings.some((x) => x.severity === "fail")
    ? "fail"
    : findings.some((x) => x.severity === "warn")
    ? "warn"
    : "ok";
  return { findings, verdict };
}

// ---------------------------------------------------------------------------
// Resource schemas
// ---------------------------------------------------------------------------

const HealthSchema = z.object({
  host: z.string(),
  checkedAt: z.string(),
  reachable: z.boolean(),
  authOk: z.boolean(),
  verdict: z.enum(["ok", "warn", "fail"]),
  findings: z.array(FindingSchema),
  model: z.string().nullable(),
  firmware: z.string().nullable(),
  latestFirmware: z.string().nullable(),
  updateAvailable: z.boolean().nullable(),
  kvmdVersion: z.string().nullable(),
  kernel: z.string().nullable(),
  serial: z.string().nullable(),
  atxEnabled: z.boolean().nullable(),
  hidOnline: z.boolean().nullable(),
  videoOnline: z.boolean().nullable().describe(
    "HDMI signal present. Null when checkVideo was off.",
  ),
  resolution: z.string().nullable(),
  msd: z.object({
    enabled: z.boolean(),
    connected: z.boolean(),
    image: z.string().nullable(),
    images: z.array(z.string()),
    freeBytes: z.number().nullable(),
    partitionConnected: z.boolean().describe(
      "GL.iNet's own storage partition is attached to the target as a USB drive.",
    ),
  }).nullable(),
  twoFactorEnabled: z.boolean().nullable(),
  webtermEnabled: z.boolean().nullable(),
  certNotAfter: z.string().nullable(),
  error: z.string().nullable(),
});

const AtxSchema = z.object({
  host: z.string(),
  at: z.string(),
  action: z.string(),
  applied: z.boolean(),
  outcome: z.enum(["status", "dry-run", "done", "refused"]),
  message: z.string(),
  enabled: z.boolean(),
  powerBefore: z.string().nullable().describe(
    "Power LED state. Null when there is no ATX board: kvmd reports 'off' " +
      "in that case regardless of the real state.",
  ),
  powerAfter: z.string().nullable(),
});

const MsdSchema = z.object({
  host: z.string(),
  at: z.string(),
  action: z.string(),
  applied: z.boolean(),
  outcome: z.enum(["status", "dry-run", "done", "refused"]),
  message: z.string(),
  enabled: z.boolean(),
  connected: z.boolean(),
  image: z.string().nullable(),
  cdrom: z.boolean().nullable(),
  images: z.array(z.object({ name: z.string(), size: z.number().nullable() })),
  freeBytes: z.number().nullable(),
});

const ScreenshotMetaSchema = z.object({
  host: z.string(),
  takenAt: z.string(),
  signal: z.boolean(),
  resolution: z.string().nullable(),
  bytes: z.number(),
  waitedMs: z.number(),
  text: z.string().nullable().describe(
    "OCR text when requested and supported.",
  ),
});

// ---------------------------------------------------------------------------
// Helpers shared by methods
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Summarise `/api/msd` into the shape both `health` and `msd` record. */
export function summariseMsd(m: Json): {
  enabled: boolean;
  connected: boolean;
  image: string | null;
  cdrom: boolean | null;
  images: { name: string; size: number | null }[];
  freeBytes: number | null;
  busy: boolean;
  partitionConnected: boolean;
} {
  const images = Object.entries(m?.storage?.images ?? {}).map(
    ([name, v]) => ({ name, size: (v as Json)?.size ?? null }),
  );
  const parts = Object.values(m?.storage?.parts ?? {}) as Json[];
  const drive = m?.drive ?? {};
  return {
    enabled: Boolean(m?.enabled),
    connected: Boolean(drive.connected),
    image: drive.image?.name ?? null,
    cdrom: typeof drive.cdrom === "boolean" ? drive.cdrom : null,
    images,
    freeBytes: parts.length ? Number(parts[0]?.free ?? 0) : null,
    busy: Boolean(m?.busy),
    // GL.iNet firmware can also expose the KVM's own storage partition to the
    // target as a USB drive, independently of the image drive.
    partitionConnected: Boolean(m?.drive_partition?.connected),
  };
}

/**
 * The source resolution: kvmd's `real_resolution` ("2560x1440@60") when the
 * firmware reports it, else the `resolution` object.
 */
export function resolutionOf(src: Json): string | null {
  const real = typeof src?.real_resolution === "string"
    ? src.real_resolution.split("@")[0]
    : "";
  if (/^\d+x\d+$/.test(real)) return real;
  const r = src?.resolution;
  return r?.width ? `${r.width}x${r.height}` : null;
}

/** Wait for the woken streamer to report its source; null if it never does. */
async function waitForSource(
  t: Transport,
  timeoutMs: number,
): Promise<{ online: boolean; resolution: string | null } | null> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const s: Json = await getJson(t, "/api/streamer");
    const src = s?.streamer?.source;
    // The first report after waking can carry a placeholder resolution from
    // before capture starts (seen: 1920x1080 for a 2560x1440 source). Trust it
    // once frames are flowing, or once the streamer says there is no signal.
    if (
      src &&
      (src.online === false || (src.online === true && src.captured_fps > 0))
    ) {
      return {
        online: src.online,
        resolution: src.online ? resolutionOf(src) : null,
      };
    }
    await sleep(500);
  }
  return null;
}

interface Ctx {
  globalArgs: GlobalArgs;
  writeResource: (
    spec: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<unknown>;
  createFileWriter: (spec: string, name: string) => {
    writeAll(content: Uint8Array): Promise<unknown>;
  };
  logger: {
    info: (msg: string, props?: Record<string, unknown>) => void;
    warn: (msg: string, props?: Record<string, unknown>) => void;
  };
}

const ATX_ACTIONS = {
  on: { path: "/api/atx/power", query: { action: "on" } },
  off: { path: "/api/atx/power", query: { action: "off" } },
  off_hard: { path: "/api/atx/power", query: { action: "off_hard" } },
  reset_hard: { path: "/api/atx/power", query: { action: "reset_hard" } },
  click_power: { path: "/api/atx/click", query: { button: "power" } },
  click_power_long: { path: "/api/atx/click", query: { button: "power_long" } },
  click_reset: { path: "/api/atx/click", query: { button: "reset" } },
} as const;

type AtxAction = keyof typeof ATX_ACTIONS;

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/**
 * The `@sntxrr/glinet-kvm` model: health, screenshots, ATX power and virtual
 * media for one GL.iNet KVM.
 */
export const model = {
  type: "@sntxrr/glinet-kvm",
  version: "2026.10.02.1",
  globalArguments: GlobalArgsSchema,

  resources: {
    health: {
      description: "Device health, firmware currency and security posture.",
      schema: HealthSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
    atx: {
      description: "ATX board state and the outcome of a power action.",
      schema: AtxSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
    msd: {
      description: "Virtual media state and the outcome of an MSD action.",
      schema: MsdSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
    screenshotMeta: {
      description: "Facts about the most recent screenshot.",
      schema: ScreenshotMetaSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
  },

  files: {
    screenshot: {
      description: "JPEG frame of the target's screen.",
      contentType: "image/jpeg",
      lifetime: "30d",
      garbageCollection: 20,
    },
  },

  methods: {
    health: {
      description:
        "Read-only health check: reachability, auth, firmware currency, HDMI signal, USB HID, attached virtual media, clock skew, ATX presence and security posture (2FA, web terminal, TLS). Records an unreachable device as verdict 'fail' rather than throwing, so a scheduled check always leaves a record.",
      arguments: z.object({
        checkVideo: z.boolean().default(true).describe(
          "Wake the streamer with a receive-only viewer session to test for an HDMI signal. Sends no input.",
        ),
        checkFirmware: z.boolean().default(true).describe(
          "Ask the device whether newer firmware exists (the device queries GL.iNet).",
        ),
        strictSecurity: z.boolean().default(false).describe(
          "Promote security-posture findings (2FA off, web terminal on, untrusted TLS) from info to warn.",
        ),
        maxClockSkewSeconds: z.number().int().positive().default(300).describe(
          "Clock difference tolerated before a clock_skew warning.",
        ),
      }),
      execute: async (
        args: {
          checkVideo: boolean;
          checkFirmware: boolean;
          strictSecurity: boolean;
          maxClockSkewSeconds: number;
        },
        context: Ctx,
      ): Promise<{ dataHandles: unknown[] }> => {
        const g = context.globalArgs;
        const t = transportFactory.create(g);
        const checkedAt = new Date();
        const blank = {
          host: g.host,
          checkedAt: checkedAt.toISOString(),
          model: null,
          firmware: null,
          latestFirmware: null,
          updateAvailable: null,
          kvmdVersion: null,
          kernel: null,
          serial: null,
          atxEnabled: null,
          hidOnline: null,
          videoOnline: null,
          resolution: null,
          msd: null,
          twoFactorEnabled: null,
          webtermEnabled: null,
          certNotAfter: null,
        };

        // Reachability and auth first: a down device is a record, not a throw.
        let authStatus: number;
        try {
          authStatus = (await t.request("GET", "/api/auth/check")).status;
        } catch (e) {
          const msg = (e as Error).message;
          context.logger.warn("KVM {host} unreachable: {msg}", {
            host: g.host,
            msg,
          });
          const h = await context.writeResource("health", "health", {
            ...blank,
            reachable: false,
            authOk: false,
            verdict: "fail",
            findings: [{ severity: "fail", code: "unreachable", message: msg }],
            error: msg,
          });
          return { dataHandles: [h] };
        }
        if (authStatus !== 200) {
          const msg = `auth check returned HTTP ${authStatus}`;
          const h = await context.writeResource("health", "health", {
            ...blank,
            reachable: true,
            authOk: false,
            verdict: "fail",
            findings: [{
              severity: "fail",
              code: "auth_failed",
              message: `${msg}; check the password (or two-factor auth is on)`,
            }],
            error: msg,
          });
          return { dataHandles: [h] };
        }

        // Past auth, a failing endpoint is still a record, not a throw: the
        // scheduled check must leave something to alert on.
        let info: Json, sys: Json, version: Json, atx: Json, hid: Json;
        let msd: ReturnType<typeof summariseMsd>;
        try {
          info = await getJson(t, "/api/info");
          sys = (await getJson(t, "/api/info", { fields: "system" }) as Json)
            ?.system;
          version = await getJson(t, "/api/upgrade/version");
          atx = await getJson(t, "/api/atx");
          msd = summariseMsd(await getJson(t, "/api/msd"));
          hid = await getJson(t, "/api/hid");
        } catch (e) {
          const msg = (e as Error).message;
          context.logger.warn("KVM {host} API error: {msg}", {
            host: g.host,
            msg,
          });
          const h = await context.writeResource("health", "health", {
            ...blank,
            reachable: true,
            authOk: true,
            verdict: "fail",
            findings: [{ severity: "fail", code: "api_error", message: msg }],
            error: msg,
          });
          return { dataHandles: [h] };
        }
        const tfa: Json = await getJson(t, "/api/2fa/is_enabled").catch(() =>
          null
        );
        const time: Json = await getJson(t, "/api/system/time").catch(() =>
          null
        );

        let latest: string | null = null;
        if (args.checkFirmware) {
          // The device asks GL.iNet's servers; an outage there is not a KVM fault.
          const cmp: Json = await getJson(t, "/api/upgrade/compare").catch(
            (e) => {
              context.logger.warn("firmware compare failed: {msg}", {
                msg: (e as Error).message,
              });
              return null;
            },
          );
          latest = cmp?.server_version || null;
        }

        let video = { checked: false, online: null as boolean | null };
        let resolution: string | null = null;
        let viewerError: string | null = null;
        if (args.checkVideo) {
          try {
            const viewer = await t.openViewer();
            try {
              const src = await waitForSource(t, g.timeoutMs);
              video = { checked: true, online: src?.online ?? false };
              resolution = src?.resolution ?? null;
            } finally {
              await viewer.close();
            }
          } catch (e) {
            // Video stays unchecked; the failure is a finding, not a lost record.
            viewerError = (e as Error).message;
          }
        }

        const cert = await t.peerCertificate().catch(() => null);
        const webterm = Boolean(info?.extras?.webterm?.enabled);
        const { findings, verdict } = evaluateHealth({
          host: g.host,
          checkedAt,
          firmware: version?.version ?? null,
          latestFirmware: latest,
          deviceTime: typeof time?.time === "number" ? time.time : null,
          atxEnabled: Boolean(atx?.enabled),
          msdConnected: msd.connected,
          msdImage: msd.image,
          partitionConnected: msd.partitionConnected,
          hidOnline: typeof hid?.online === "boolean" ? hid.online : null,
          twoFactorEnabled: typeof tfa?.enabled === "boolean"
            ? tfa.enabled
            : null,
          webtermEnabled: webterm,
          video,
          viewerError,
          cert,
          strictSecurity: args.strictSecurity,
          maxClockSkewSeconds: args.maxClockSkewSeconds,
        });

        context.logger.info("KVM {host}: {verdict} ({n} findings)", {
          host: g.host,
          verdict,
          n: findings.length,
        });
        const h = await context.writeResource("health", "health", {
          ...blank,
          reachable: true,
          authOk: true,
          verdict,
          findings,
          model: version?.model ?? null,
          firmware: version?.version ?? null,
          latestFirmware: latest,
          updateAvailable: latest && version?.version
            ? latest !== version.version
            : null,
          kvmdVersion: sys?.kvmd?.version ?? null,
          kernel: sys?.kernel?.release ?? null,
          serial: sys?.platform?.serial ?? null,
          atxEnabled: Boolean(atx?.enabled),
          hidOnline: typeof hid?.online === "boolean" ? hid.online : null,
          videoOnline: video.checked ? video.online : null,
          resolution,
          msd: {
            enabled: msd.enabled,
            connected: msd.connected,
            image: msd.image,
            images: msd.images.map((i) => i.name),
            freeBytes: msd.freeBytes,
            partitionConnected: msd.partitionConnected,
          },
          twoFactorEnabled: typeof tfa?.enabled === "boolean"
            ? tfa.enabled
            : null,
          webtermEnabled: webterm,
          certNotAfter: cert?.notAfter ?? null,
          error: null,
        });
        return { dataHandles: [h] };
      },
    },

    screenshot: {
      description:
        "Capture a JPEG of the target's screen. Wakes the streamer with a receive-only viewer session (no input is sent), waits for a frame, and stores it as the `screenshot` file. Fails, after recording screenshotMeta, when there is no HDMI signal.",
      arguments: z.object({
        ocr: z.boolean().default(false).describe(
          "Also ask kvmd to OCR the frame and store the text in screenshotMeta.",
        ),
        waitMs: z.number().int().positive().default(15000).describe(
          "How long to wait for the woken streamer to produce a frame.",
        ),
      }),
      execute: async (
        args: { ocr: boolean; waitMs: number },
        context: Ctx,
      ): Promise<{ dataHandles: unknown[] }> => {
        const g = context.globalArgs;
        const t = transportFactory.create(g);
        const started = Date.now();
        const viewer = await t.openViewer();
        let frame: Uint8Array | null = null;
        let src: { online: boolean; resolution: string | null } | null = null;
        let text: string | null = null;
        try {
          src = await waitForSource(t, args.waitMs);
          if (src?.online) {
            const deadline = started + args.waitMs;
            while (Date.now() < deadline) {
              const r = await t.request("GET", "/api/streamer/snapshot");
              if (r.status === 200 && r.contentType.startsWith("image/")) {
                frame = r.body;
                break;
              }
              await sleep(500);
            }
            if (frame && args.ocr) {
              const r = await t.request("GET", "/api/streamer/snapshot", {
                query: { ocr: "1" },
              });
              if (r.status === 200 && r.contentType.startsWith("text/")) {
                text = new TextDecoder().decode(r.body);
              } else {
                context.logger.warn("OCR unavailable: HTTP {status} {type}", {
                  status: r.status,
                  type: r.contentType,
                });
              }
            }
          }
        } finally {
          await viewer.close();
        }

        const handles: unknown[] = [];
        if (frame) {
          handles.push(
            await context.createFileWriter("screenshot", "screenshot").writeAll(
              frame,
            ),
          );
        }
        handles.push(
          await context.writeResource("screenshotMeta", "screenshotMeta", {
            host: g.host,
            takenAt: new Date().toISOString(),
            signal: Boolean(src?.online),
            resolution: src?.resolution ?? null,
            bytes: frame?.length ?? 0,
            waitedMs: Date.now() - started,
            text,
          }),
        );
        if (!frame) {
          throw new Error(
            src?.online === false
              ? `no HDMI signal on ${g.host}: the streamer is up but the target is not sending video`
              : `no frame from ${g.host} within ${args.waitMs}ms`,
          );
        }
        return { dataHandles: handles };
      },
    },

    atx: {
      description:
        "Read ATX state or drive the target's power/reset buttons. Dry run unless apply is true. Refuses any button action when the KVM has no ATX board, since kvmd would accept it and nothing would happen.",
      arguments: z.object({
        action: z.enum([
          "status",
          "on",
          "off",
          "off_hard",
          "reset_hard",
          "click_power",
          "click_power_long",
          "click_reset",
        ]).default("status").describe(
          "on/off are soft (power button, only if state differs); off_hard holds power; reset_hard pulses reset; click_* press a button unconditionally.",
        ),
        apply: z.boolean().default(false).describe(
          "Actually press the button. Without it, report what would happen.",
        ),
      }),
      execute: async (
        args: { action: "status" | AtxAction; apply: boolean },
        context: Ctx,
      ): Promise<{ dataHandles: unknown[] }> => {
        const g = context.globalArgs;
        const t = transportFactory.create(g);
        const before: Json = await getJson(t, "/api/atx");
        const enabled = Boolean(before?.enabled);
        const powerOf = (
          s: Json,
        ): string | null => (s?.enabled ? s.power ?? null : null);
        const base = {
          host: g.host,
          at: new Date().toISOString(),
          action: args.action,
          enabled,
          powerBefore: powerOf(before),
        };
        const write = (rec: Record<string, unknown>) =>
          context.writeResource("atx", "atx", { ...base, ...rec });

        if (args.action === "status") {
          const h = await write({
            applied: false,
            outcome: "status",
            message: enabled
              ? `power is ${before.power}`
              : "no ATX board: power state unknown",
            powerAfter: powerOf(before),
          });
          return { dataHandles: [h] };
        }
        if (!enabled) {
          await write({
            applied: false,
            outcome: "refused",
            message:
              `refused ${args.action}: no ATX board is attached, so the press would do nothing`,
            powerAfter: null,
          });
          throw new Error(
            `${g.host} has no ATX board; refusing ${args.action}`,
          );
        }
        if (before?.busy) {
          await write({
            applied: false,
            outcome: "refused",
            message: "refused: an ATX operation is already in progress",
            powerAfter: powerOf(before),
          });
          throw new Error(`${g.host} ATX is busy`);
        }
        const op = ATX_ACTIONS[args.action];
        if (!args.apply) {
          const h = await write({
            applied: false,
            outcome: "dry-run",
            message: `would POST ${op.path}?${new URLSearchParams(
              op.query,
            )} (power is ${before.power}); pass apply: true to act`,
            powerAfter: powerOf(before),
          });
          return { dataHandles: [h] };
        }
        context.logger.warn("ATX {action} on {host}", {
          action: args.action,
          host: g.host,
        });
        await postJson(t, op.path, { ...op.query, wait: "1" });
        const after: Json = await getJson(t, "/api/atx");
        const h = await write({
          applied: true,
          outcome: "done",
          message:
            `${args.action} sent; power was ${before.power}, now ${after?.power}`,
          powerAfter: powerOf(after),
        });
        return { dataHandles: [h] };
      },
    },

    msd: {
      description:
        "Virtual media (mass storage). status lists images and what is attached; upload streams a local ISO to the KVM; download has the KVM fetch a URL itself; connect attaches an image to the target as a CD-ROM or flash drive; disconnect detaches; remove deletes an image. Every action but status is a dry run unless apply is true.",
      arguments: z.object({
        action: z.enum([
          "status",
          "upload",
          "download",
          "connect",
          "disconnect",
          "remove",
        ])
          .default("status"),
        image: z.string().optional().describe(
          "Image name on the KVM. Required for upload, download, connect, remove.",
        ),
        file: z.string().optional().describe(
          "Local path to upload (upload only).",
        ),
        url: z.string().url().optional().describe(
          "URL the KVM downloads itself (download only). Better than upload for large ISOs over a slow link.",
        ),
        cdrom: z.boolean().default(true).describe(
          "connect: present as a CD-ROM (true) or a writable flash drive (false).",
        ),
        transferTimeoutMs: z.number().int().positive().default(3_600_000)
          .describe(
            "Timeout for upload and download.",
          ),
        apply: z.boolean().default(false).describe(
          "Actually change the device. Without it, report what would happen.",
        ),
      }),
      execute: async (
        args: {
          action:
            | "status"
            | "upload"
            | "download"
            | "connect"
            | "disconnect"
            | "remove";
          image?: string;
          file?: string;
          url?: string;
          cdrom: boolean;
          transferTimeoutMs: number;
          apply: boolean;
        },
        context: Ctx,
      ): Promise<{ dataHandles: unknown[] }> => {
        const g = context.globalArgs;
        const t = transportFactory.create(g);
        const state = summariseMsd(await getJson(t, "/api/msd"));
        const record = (
          s: ReturnType<typeof summariseMsd>,
          rec: { applied: boolean; outcome: string; message: string },
        ) =>
          context.writeResource("msd", "msd", {
            host: g.host,
            at: new Date().toISOString(),
            action: args.action,
            ...rec,
            enabled: s.enabled,
            connected: s.connected,
            image: s.image,
            cdrom: s.cdrom,
            images: s.images,
            freeBytes: s.freeBytes,
          });
        const refuse = async (why: string): Promise<never> => {
          await record(state, {
            applied: false,
            outcome: "refused",
            message: why,
          });
          throw new Error(`msd ${args.action} on ${g.host}: ${why}`);
        };

        if (args.action === "status") {
          const h = await record(state, {
            applied: false,
            outcome: "status",
            message: state.connected
              ? `attached: ${state.image ?? "(unnamed)"}`
              : `${state.images.length} image(s), nothing attached`,
          });
          return { dataHandles: [h] };
        }

        if (!state.enabled) {
          await refuse("virtual media is disabled on this device");
        }
        if (state.busy) await refuse("an MSD operation is already in progress");
        const needsImage = ["upload", "download", "connect", "remove"].includes(
          args.action,
        );
        if (needsImage && !args.image) await refuse("`image` is required");
        const name = args.image ?? "";
        const exists = state.images.some((i) => i.name === name);

        let plan: {
          path: string;
          query: Record<string, string>;
          opts?: RequestOptions;
        }[] = [];
        switch (args.action) {
          case "upload": {
            if (!args.file) await refuse("`file` is required for upload");
            const st = await Deno.stat(args.file!).catch(() => null);
            if (!st?.isFile) {
              await refuse(`${args.file} is not a readable file`);
            }
            if (exists) {
              await refuse(`image ${name} already exists; remove it first`);
            }
            if (state.freeBytes !== null && st!.size > state.freeBytes) {
              await refuse(
                `${st!.size} bytes will not fit in ${state.freeBytes} free`,
              );
            }
            plan = [{
              path: "/api/msd/write",
              query: { image: name, remove_incomplete: "1" },
              opts: {
                uploadFile: args.file,
                timeoutMs: args.transferTimeoutMs,
              },
            }];
            break;
          }
          case "download":
            if (!args.url) await refuse("`url` is required for download");
            if (exists) {
              await refuse(`image ${name} already exists; remove it first`);
            }
            plan = [{
              path: "/api/msd/write_remote",
              query: { url: args.url!, image: name, remove_incomplete: "1" },
              opts: { timeoutMs: args.transferTimeoutMs },
            }];
            break;
          case "connect":
            if (!exists) await refuse(`no image named ${name} on the device`);
            if (state.connected) {
              await refuse(
                `${
                  state.image ?? "an image"
                } is already attached; disconnect first`,
              );
            }
            plan = [
              {
                path: "/api/msd/set_params",
                query: { image: name, cdrom: args.cdrom ? "1" : "0" },
              },
              { path: "/api/msd/set_connected", query: { connected: "1" } },
            ];
            break;
          case "disconnect":
            if (!state.connected) await refuse("nothing is attached");
            plan = [{
              path: "/api/msd/set_connected",
              query: { connected: "0" },
            }];
            break;
          case "remove":
            if (!exists) await refuse(`no image named ${name} on the device`);
            if (state.connected && state.image === name) {
              await refuse(
                `${name} is attached to the target; disconnect first`,
              );
            }
            plan = [{ path: "/api/msd/remove", query: { image: name } }];
            break;
        }

        const describe = plan.map((p) =>
          `POST ${p.path}?${new URLSearchParams(p.query)}`
        )
          .join(", then ");
        if (!args.apply) {
          const h = await record(state, {
            applied: false,
            outcome: "dry-run",
            message: `would ${describe}; pass apply: true to act`,
          });
          return { dataHandles: [h] };
        }
        context.logger.warn("MSD {action} on {host}: {plan}", {
          action: args.action,
          host: g.host,
          plan: describe,
        });
        for (const p of plan) await postJson(t, p.path, p.query, p.opts);
        const after = summariseMsd(await getJson(t, "/api/msd"));
        const h = await record(after, {
          applied: true,
          outcome: "done",
          message: `${args.action} done: ${describe}`,
        });
        return { dataHandles: [h] };
      },
    },
  },
};
