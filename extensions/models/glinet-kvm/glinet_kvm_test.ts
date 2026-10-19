// Tests hand the scripted context to execute() as `any`, as sibling extensions do.
// deno-lint-ignore-file no-explicit-any
import {
  assert,
  assertEquals,
  assertRejects,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20260928.39";
import {
  type CertInfo,
  certMatchesHost,
  checkReadCache,
  CliTransport,
  curlConfig,
  curlQuote,
  driveInvisible,
  evaluateHealth,
  type HealthFacts,
  type HttpResult,
  model,
  msdSettle,
  parseCertText,
  redactUrl,
  type RequestOptions,
  resolutionOf,
  summariseMsd,
  type Transport,
  transportFactory,
  unwrap,
  viewerHandshake,
} from "./glinet_kvm.ts";

// Fakes that never change state would otherwise wait out the real settle window.
msdSettle.timeoutMs = 50;
msdSettle.intervalMs = 1;

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

const G = model.globalArguments.parse({
  host: "192.0.2.10",
  password: 'pa"ss\\word',
});

Deno.test("curlQuote escapes quotes, backslashes and control characters", () => {
  assertEquals(curlQuote('a"b'), '"a\\"b"');
  assertEquals(curlQuote("a\\b"), '"a\\\\b"');
  assertEquals(curlQuote("a\nb"), '"a\\nb"');
});

Deno.test("curlConfig carries the password quoted, disables verification, sets a timeout", () => {
  const cfg = curlConfig(G, "GET", "/api/info", "/tmp/out", {
    query: { fields: "system" },
  });
  assertStringIncludes(cfg, 'header = "X-KVMD-Passwd: pa\\"ss\\\\word"');
  assertStringIncludes(cfg, "\ninsecure\n");
  assertStringIncludes(
    cfg,
    'url = "https://192.0.2.10:443/api/info?fields=system"',
  );
  assertStringIncludes(cfg, "max-time = 15");
  assert(!cfg.includes("data-binary"));
});

Deno.test("curlConfig streams an upload file and sends an empty body on bare POST", () => {
  const up = curlConfig(G, "POST", "/api/msd/write", "/tmp/o", {
    uploadFile: "/isos/x.iso",
  });
  assertStringIncludes(up, 'data-binary = "@/isos/x.iso"');
  const bare = curlConfig(G, "POST", "/api/msd/set_connected", "/tmp/o", {});
  assertStringIncludes(bare, 'data = ""');
});

Deno.test("viewer handshake is a websocket upgrade to /api/ws with header auth", () => {
  const h = viewerHandshake(G, "a2V5");
  assert(h.startsWith("GET /api/ws?stream=1 HTTP/1.1\r\n"));
  assertStringIncludes(h, "Upgrade: websocket\r\n");
  assertStringIncludes(h, "X-KVMD-User: admin\r\n");
  assert(h.endsWith("\r\n\r\n"));
});

const FACTORY_CERT_TEXT = `Certificate:
    Data:
        Issuer: C=US, O=GLKVM, OU=GLKVM, CN=localhost
        Validity
            Not Before: Jan  1 00:00:14 1970 GMT
            Not After : Dec 30 00:00:14 1979 GMT
        Subject: C=US, O=GLKVM, OU=GLKVM, CN=localhost
`;

Deno.test("parseCertText reads the factory certificate", () => {
  const c = parseCertText(FACTORY_CERT_TEXT);
  assertEquals(c.subject, "C=US, O=GLKVM, OU=GLKVM, CN=localhost");
  assertEquals(c.issuer, c.subject);
  assertEquals(c.notAfter, "1979-12-30T00:00:14.000Z");
  assertEquals(c.sans, []);
});

Deno.test("parseCertText collects DNS and IP SANs", () => {
  const c = parseCertText(
    FACTORY_CERT_TEXT +
      "            X509v3 Subject Alternative Name: \n                DNS:kvm-a.example.net, IP Address:192.0.2.10\n",
  );
  assertEquals(c.sans, ["kvm-a.example.net", "192.0.2.10"]);
  assert(certMatchesHost(c, "192.0.2.10"));
  assert(!certMatchesHost(c, "localhost"), "SANs take precedence over the CN");
});

Deno.test("certMatchesHost falls back to the CN only when there are no SANs", () => {
  const c = parseCertText(FACTORY_CERT_TEXT);
  assert(certMatchesHost(c, "localhost"));
  assert(!certMatchesHost(c, "192.0.2.10"));
});

Deno.test("unwrap returns result on ok and names kvmd's error otherwise", () => {
  const enc = (o: unknown): HttpResult => ({
    status: 401,
    contentType: "application/json",
    body: new TextEncoder().encode(JSON.stringify(o)),
  });
  assertEquals(
    unwrap("/x", { ...enc({ ok: true, result: { a: 1 } }), status: 200 }),
    { a: 1 },
  );
  try {
    unwrap(
      "/x",
      enc({
        ok: false,
        result: { error: "UnauthorizedError", error_msg: "Unauthorized" },
      }),
    );
    throw new Error("should have thrown");
  } catch (e) {
    assertStringIncludes((e as Error).message, "UnauthorizedError");
  }
});

Deno.test("unwrap accepts a streamed response and returns the final line", () => {
  // Shape of msd write_remote on firmware V1.9.1: one envelope per progress
  // step. Seen live as `{"ok": true, "result": {"image": {..., "written": 0`.
  const lines = [0, 852000000, 1706178560].map((w) =>
    JSON.stringify({
      ok: true,
      result: { image: { name: "a.iso", size: 1706178560, written: w } },
    })
  );
  const body = new TextEncoder().encode(lines.join("\n") + "\n");
  const r = unwrap("/api/msd/write_remote", {
    status: 200,
    contentType: "application/x-ndjson",
    body,
  }) as { image: { written: number } };
  assertEquals(r.image.written, 1706178560);
});

Deno.test("unwrap fails a stream when any line failed", () => {
  const body = new TextEncoder().encode(
    JSON.stringify({ ok: true, result: { image: { written: 0 } } }) + "\n" +
      JSON.stringify({
        ok: false,
        result: { error: "MsdError", error_msg: "remote closed" },
      }) + "\n",
  );
  try {
    unwrap("/api/msd/write_remote", { status: 200, contentType: "", body });
    throw new Error("should have thrown");
  } catch (e) {
    assertStringIncludes((e as Error).message, "remote closed");
  }
});

Deno.test("unwrap still rejects text that is not kvmd JSON", () => {
  const body = new TextEncoder().encode("<html>404</html>\n");
  try {
    unwrap("/x", { status: 404, contentType: "text/html", body });
    throw new Error("should have thrown");
  } catch (e) {
    assertStringIncludes((e as Error).message, "not a kvmd response");
  }
});

Deno.test("summariseMsd reports attachment, images and free space", () => {
  const s = summariseMsd({
    enabled: true,
    busy: false,
    drive: { connected: true, cdrom: true, image: { name: "rescue.iso" } },
    storage: {
      images: { "rescue.iso": { size: 10 } },
      parts: { "": { free: 99 } },
    },
  });
  assertEquals(s.connected, true);
  assertEquals(s.image, "rescue.iso");
  assertEquals(s.images, [{ name: "rescue.iso", size: 10 }]);
  assertEquals(s.freeBytes, 99);
});

Deno.test("resolutionOf prefers real_resolution and strips the refresh rate", () => {
  assertEquals(
    resolutionOf({
      real_resolution: "2560x1440@60",
      resolution: { width: 1920, height: 1080 },
    }),
    "2560x1440",
  );
  assertEquals(
    resolutionOf({ resolution: { width: 1920, height: 1080 } }),
    "1920x1080",
  );
  assertEquals(resolutionOf({ resolution: { width: 0, height: 0 } }), null);
});

Deno.test("screenshot waits past the placeholder report until frames flow", async () => {
  let polls = 0;
  const fake = new FakeKvm(healthyRoutes({
    "GET /api/streamer": () => {
      polls++;
      return polls === 1
        ? {
          json: {
            ok: true,
            result: {
              streamer: {
                source: {
                  online: true,
                  captured_fps: 0,
                  resolution: { width: 1920, height: 1080 },
                },
              },
            },
          },
        }
        : {
          json: {
            ok: true,
            result: {
              streamer: {
                source: {
                  online: true,
                  captured_fps: 11,
                  real_resolution: "2560x1440@60",
                },
              },
            },
          },
        };
    },
  }));
  const { context, getWrittenResources } = ctx();
  await withFake(
    fake,
    () =>
      model.methods.screenshot.execute(
        parseArgs("screenshot", {}),
        context as any,
      ),
  );
  assertEquals(
    getWrittenResources().find((r) => r.specName === "screenshotMeta")!.data
      .resolution,
    "2560x1440",
  );
});

// ---------------------------------------------------------------------------
// evaluateHealth
// ---------------------------------------------------------------------------

const NOW = new Date("2026-10-02T12:00:00Z");
const FACTORY_CERT: CertInfo = parseCertText(FACTORY_CERT_TEXT);

function facts(over: Partial<HealthFacts> = {}): HealthFacts {
  return {
    host: "192.0.2.10",
    checkedAt: NOW,
    firmware: "V1.9.1 release1",
    latestFirmware: "V1.9.1 release1",
    deviceTime: NOW.getTime() / 1000,
    atxEnabled: false,
    msdConnected: false,
    msdImage: null,
    msdInvisible: false,
    partitionConnected: false,
    hidOnline: true,
    twoFactorEnabled: false,
    webtermEnabled: true,
    video: { checked: true, online: true },
    viewerError: null,
    cert: FACTORY_CERT,
    strictSecurity: false,
    maxClockSkewSeconds: 300,
    tailscale: null,
    tailnet: null,
    ...over,
  };
}

Deno.test("a factory-default device with current firmware is ok: posture findings are info", () => {
  const { verdict, findings } = evaluateHealth(facts());
  assertEquals(verdict, "ok");
  const codes = findings.map((f) => f.code).sort();
  assertEquals(codes, [
    "atx_absent",
    "tls_untrusted",
    "two_factor_disabled",
    "webterm_enabled",
  ]);
  assert(findings.every((f) => f.severity === "info"));
  const tls = findings.find((f) => f.code === "tls_untrusted")!;
  assertStringIncludes(tls.message, "self-signed");
  assertStringIncludes(tls.message, "expired 1979-12-30");
});

Deno.test("strictSecurity promotes posture findings to warn", () => {
  const { verdict, findings } = evaluateHealth(facts({ strictSecurity: true }));
  assertEquals(verdict, "warn");
  assertEquals(
    findings.find((f) => f.code === "webterm_enabled")!.severity,
    "warn",
  );
  // ATX absence is a hardware fact, not a posture choice.
  assertEquals(findings.find((f) => f.code === "atx_absent")!.severity, "info");
});

Deno.test("a newer firmware release warns", () => {
  const { verdict, findings } = evaluateHealth(
    facts({ latestFirmware: "V1.10.1 release2" }),
  );
  assertEquals(verdict, "warn");
  assertStringIncludes(
    findings.find((f) => f.code === "firmware_update_available")!.message,
    "V1.10.1",
  );
});

Deno.test("an unknown latest firmware does not warn", () => {
  assertEquals(evaluateHealth(facts({ latestFirmware: null })).verdict, "ok");
});

Deno.test("no HDMI signal warns only when video was checked", () => {
  assertEquals(
    evaluateHealth(facts({ video: { checked: true, online: false } })).verdict,
    "warn",
  );
  assertEquals(
    evaluateHealth(facts({ video: { checked: false, online: null } })).verdict,
    "ok",
  );
});

Deno.test("attached virtual media warns: the next reboot may boot it", () => {
  const { verdict, findings } = evaluateHealth(
    facts({ msdConnected: true, msdImage: "rescue.iso" }),
  );
  assertEquals(verdict, "warn");
  assertStringIncludes(
    findings.find((f) => f.code === "virtual_media_attached")!.message,
    "rescue.iso",
  );
});

Deno.test("clock skew beyond the tolerance warns", () => {
  const skewed = facts({ deviceTime: NOW.getTime() / 1000 - 3600 });
  assertEquals(
    evaluateHealth(skewed).findings.some((f) => f.code === "clock_skew"),
    true,
  );
  assertEquals(
    evaluateHealth(facts({ deviceTime: NOW.getTime() / 1000 - 60 })).verdict,
    "ok",
  );
});

Deno.test("GL.iNet's storage partition attached to the target warns", () => {
  assertEquals(
    evaluateHealth(facts({ partitionConnected: true })).findings.some((f) =>
      f.code === "storage_partition_attached"
    ),
    true,
  );
});

Deno.test("CR or LF in credentials is rejected before it can inject a header", () => {
  assertEquals(
    model.globalArguments.safeParse({ host: "h", password: "a\r\nX-Evil: 1" })
      .success,
    false,
  );
  assertEquals(
    model.globalArguments.safeParse({
      host: "h",
      username: "a\nb",
      password: "p",
    }).success,
    false,
  );
});

Deno.test("HID offline warns", () => {
  assertEquals(evaluateHealth(facts({ hidOnline: false })).verdict, "warn");
});

// ---------------------------------------------------------------------------
// Methods, against a fake transport
// ---------------------------------------------------------------------------

type Route = (
  q: Record<string, string>,
) => { status?: number; json?: unknown; raw?: Uint8Array; type?: string };

/** A scripted kvmd. Records every request so tests can prove what was NOT sent. */
class FakeKvm implements Transport {
  calls: {
    method: string;
    path: string;
    query: Record<string, string>;
    anonymous?: boolean;
  }[] = [];
  viewers = 0;
  closed = 0;
  constructor(
    private routes: Record<string, Route>,
    private opts: { unreachable?: boolean; cert?: CertInfo | null } = {},
  ) {}

  request(
    method: "GET" | "POST",
    path: string,
    o: RequestOptions = {},
  ): Promise<HttpResult> {
    if (this.opts.unreachable) {
      return Promise.reject(
        new Error(`GET ${path} failed (curl exit 7): Failed to connect`),
      );
    }
    const query = o.query ?? {};
    this.calls.push({
      method,
      path,
      query,
      ...(o.anonymous ? { anonymous: true } : {}),
    });
    const route = this.routes[`${method} ${path}`];
    if (!route) {
      return Promise.resolve({
        status: 404,
        contentType: "text/plain",
        body: new TextEncoder().encode("404"),
      });
    }
    const r = route(query);
    return Promise.resolve({
      status: r.status ?? 200,
      contentType: r.type ?? "application/json",
      body: r.raw ?? new TextEncoder().encode(JSON.stringify(r.json)),
    });
  }

  openViewer() {
    this.viewers++;
    return Promise.resolve({ close: () => (this.closed++, Promise.resolve()) });
  }

  peerCertificate() {
    return Promise.resolve(
      this.opts.cert === undefined ? FACTORY_CERT : this.opts.cert,
    );
  }

  posts() {
    return this.calls.filter((c) => c.method === "POST");
  }
}

const ok = (result: unknown) => () => ({ json: { ok: true, result } });

function healthyRoutes(
  over: Record<string, Route> = {},
): Record<string, Route> {
  return {
    "GET /api/auth/check": ok({}),
    "GET /api/info": (q) =>
      q.fields === "system"
        ? {
          json: {
            ok: true,
            result: {
              system: {
                kvmd: { version: "4.82" },
                kernel: { release: "6.1.141" },
                platform: { serial: "TESTSERIAL" },
              },
            },
          },
        }
        : {
          json: {
            ok: true,
            result: { extras: { webterm: { enabled: true } } },
          },
        },
    "GET /api/upgrade/version": ok({
      model: "RM1PE",
      version: "V1.9.1 release1",
    }),
    "GET /api/upgrade/compare": ok({ server_version: "V1.10.1 release2" }),
    "GET /api/atx": ok({
      enabled: false,
      busy: false,
      power: "off",
      leds: { power: false },
    }),
    "GET /api/msd": ok({
      enabled: true,
      busy: false,
      drive: { connected: false, image: null, cdrom: true },
      storage: { images: {}, parts: { "": { free: 1000 } } },
    }),
    "GET /api/hid": ok({ online: true }),
    "GET /api/2fa/is_enabled": ok({ enabled: false }),
    "GET /api/system/time": ok({ time: Math.floor(Date.now() / 1000) }),
    "GET /api/system/otg_functions": ok({
      start_cdrom: true,
      start_flash: true,
    }),
    "GET /api/streamer": ok({
      streamer: {
        source: {
          online: true,
          captured_fps: 11,
          resolution: { width: 1920, height: 1080 },
        },
      },
    }),
    "GET /api/streamer/snapshot": () => ({
      raw: new Uint8Array([0xff, 0xd8, 0xff, 0xd9]),
      type: "image/jpeg",
    }),
    ...over,
  };
}

async function withFake<T>(fake: FakeKvm, fn: () => Promise<T>): Promise<T> {
  const orig = transportFactory.create;
  transportFactory.create = () => fake;
  try {
    return await fn();
  } finally {
    transportFactory.create = orig;
  }
}

function ctx() {
  return createModelTestContext({
    globalArgs: model.globalArguments.parse({
      host: "192.0.2.10",
      password: "x",
    }),
  });
}

const parseArgs = (
  m: keyof typeof model.methods,
  a: Record<string, unknown>,
): any => model.methods[m].arguments.parse(a);

Deno.test("health records a reachable device, validates against its schema, closes the viewer", async () => {
  const fake = new FakeKvm(healthyRoutes());
  const { context, getWrittenResources } = ctx();
  await withFake(
    fake,
    () => model.methods.health.execute(parseArgs("health", {}), context as any),
  );
  const [w] = getWrittenResources();
  model.resources.health.schema.parse(w.data);
  assertEquals(w.data.verdict, "warn");
  assertEquals(w.data.updateAvailable, true);
  assertEquals(w.data.videoOnline, true);
  assertEquals(w.data.resolution, "1920x1080");
  assertEquals(w.data.kvmdVersion, "4.82");
  assertEquals(fake.viewers, 1);
  assertEquals(fake.closed, 1);
  assertEquals(fake.posts().length, 0, "health must never write to the device");
});

Deno.test("health records an unreachable device as fail instead of throwing", async () => {
  const fake = new FakeKvm({}, { unreachable: true });
  const { context, getWrittenResources } = ctx();
  await withFake(
    fake,
    () => model.methods.health.execute(parseArgs("health", {}), context as any),
  );
  const [w] = getWrittenResources();
  model.resources.health.schema.parse(w.data);
  assertEquals(w.data.reachable, false);
  assertEquals(w.data.verdict, "fail");
  assertStringIncludes(String(w.data.error), "Failed to connect");
});

Deno.test("health records a rejected password as auth_failed", async () => {
  const fake = new FakeKvm({
    "GET /api/auth/check": () => ({ status: 401, json: { ok: false } }),
  });
  const { context, getWrittenResources } = ctx();
  await withFake(
    fake,
    () => model.methods.health.execute(parseArgs("health", {}), context as any),
  );
  const [w] = getWrittenResources();
  model.resources.health.schema.parse(w.data);
  assertEquals(w.data.authOk, false);
  assertEquals((w.data.findings as any[])[0].code, "auth_failed");
});

Deno.test("health records a failing endpoint after auth as api_error instead of throwing", async () => {
  const fake = new FakeKvm(healthyRoutes({
    "GET /api/msd": () => ({
      status: 500,
      json: { ok: false, result: { error: "MsdError", error_msg: "broken" } },
    }),
  }));
  const { context, getWrittenResources } = ctx();
  await withFake(
    fake,
    () => model.methods.health.execute(parseArgs("health", {}), context as any),
  );
  const [w] = getWrittenResources();
  model.resources.health.schema.parse(w.data);
  assertEquals(w.data.verdict, "fail");
  assertEquals((w.data.findings as any[])[0].code, "api_error");
});

Deno.test("health records a refused viewer as a finding and still completes", async () => {
  const fake = new FakeKvm(healthyRoutes());
  fake.openViewer = () =>
    Promise.reject(
      new Error("viewer websocket refused: HTTP/1.1 403 Forbidden"),
    );
  const { context, getWrittenResources } = ctx();
  await withFake(
    fake,
    () => model.methods.health.execute(parseArgs("health", {}), context as any),
  );
  const [w] = getWrittenResources();
  model.resources.health.schema.parse(w.data);
  assertEquals(w.data.videoOnline, null);
  assert((w.data.findings as any[]).some((f) => f.code === "viewer_failed"));
});

Deno.test("health survives a firmware-server outage", async () => {
  const fake = new FakeKvm(healthyRoutes({
    "GET /api/upgrade/compare": () => ({
      status: 500,
      json: { ok: false, result: { error: "Error" } },
    }),
  }));
  const { context, getWrittenResources } = ctx();
  await withFake(
    fake,
    () => model.methods.health.execute(parseArgs("health", {}), context as any),
  );
  assertEquals(getWrittenResources()[0].data.latestFirmware, null);
  assertEquals(getWrittenResources()[0].data.verdict, "ok");
});

Deno.test("screenshot wakes the streamer, stores the JPEG and its metadata", async () => {
  const fake = new FakeKvm(healthyRoutes());
  const { context, getWrittenResources, getWrittenFiles } = ctx();
  await withFake(
    fake,
    () =>
      model.methods.screenshot.execute(
        parseArgs("screenshot", {}),
        context as any,
      ),
  );
  assertEquals(getWrittenFiles().length, 1);
  const meta = getWrittenResources().find((r) =>
    r.specName === "screenshotMeta"
  )!;
  model.resources.screenshotMeta.schema.parse(meta.data);
  assertEquals(meta.data.signal, true);
  assertEquals(meta.data.bytes, 4);
  assertEquals(fake.closed, 1);
});

Deno.test("screenshot with no HDMI signal records the fact, then fails", async () => {
  const fake = new FakeKvm(healthyRoutes({
    "GET /api/streamer": ok({
      streamer: {
        source: { online: false, resolution: { width: 0, height: 0 } },
      },
    }),
  }));
  const { context, getWrittenResources, getWrittenFiles } = ctx();
  await assertRejects(
    () =>
      withFake(
        fake,
        () =>
          model.methods.screenshot.execute(
            parseArgs("screenshot", { waitMs: 1000 }),
            context as any,
          ),
      ),
    Error,
    "no HDMI signal",
  );
  assertEquals(getWrittenFiles().length, 0);
  assertEquals(getWrittenResources()[0].data.signal, false);
  assertEquals(fake.closed, 1, "the viewer is closed even on failure");
});

const ATX_BOARD = ok({
  enabled: true,
  busy: false,
  power: "on",
  leds: { power: true },
});

Deno.test("atx status without a board reports power as unknown, not 'off'", async () => {
  const fake = new FakeKvm(healthyRoutes());
  const { context, getWrittenResources } = ctx();
  await withFake(
    fake,
    () => model.methods.atx.execute(parseArgs("atx", {}), context as any),
  );
  const d = getWrittenResources()[0].data;
  model.resources.atx.schema.parse(d);
  assertEquals(d.powerBefore, null);
  assertStringIncludes(String(d.message), "no ATX board");
});

Deno.test("atx refuses a button press when there is no board, even with apply", async () => {
  const fake = new FakeKvm(healthyRoutes());
  const { context, getWrittenResources } = ctx();
  await assertRejects(
    () =>
      withFake(fake, () =>
        model.methods.atxPress.execute(
          parseArgs("atxPress", { action: "reset_hard" }),
          context as any,
        )),
    Error,
    "no ATX board",
  );
  assertEquals(getWrittenResources()[0].data.outcome, "refused");
  assertEquals(fake.posts().length, 0);
});

Deno.test("atx with a board is a dry run by default", async () => {
  const fake = new FakeKvm(healthyRoutes({ "GET /api/atx": ATX_BOARD }));
  const { context, getWrittenResources } = ctx();
  await withFake(
    fake,
    () =>
      model.methods.atx.execute(
        parseArgs("atx", { action: "off" }),
        context as any,
      ),
  );
  assertEquals(getWrittenResources()[0].data.outcome, "dry-run");
  assertEquals(fake.posts().length, 0);
});

Deno.test("atx apply posts the action and waits for it", async () => {
  const fake = new FakeKvm(
    healthyRoutes({ "GET /api/atx": ATX_BOARD, "POST /api/atx/click": ok({}) }),
  );
  const { context, getWrittenResources } = ctx();
  await withFake(fake, () =>
    model.methods.atxPress.execute(
      parseArgs("atxPress", { action: "click_reset" }),
      context as any,
    ));
  assertEquals(fake.posts(), [{
    method: "POST",
    path: "/api/atx/click",
    query: { button: "reset", wait: "1" },
  }]);
  assertEquals(getWrittenResources()[0].data.outcome, "done");
});

const MSD_WITH_IMAGE = (connected: boolean) =>
  ok({
    enabled: true,
    busy: false,
    drive: {
      connected,
      cdrom: true,
      image: connected ? { name: "rescue.iso" } : null,
    },
    storage: {
      images: { "rescue.iso": { size: 10 } },
      parts: { "": { free: 1000 } },
    },
  });

Deno.test("msd connect is a dry run by default and names both calls", async () => {
  const fake = new FakeKvm(
    healthyRoutes({ "GET /api/msd": MSD_WITH_IMAGE(false) }),
  );
  const { context, getWrittenResources } = ctx();
  await withFake(fake, () =>
    model.methods.msd.execute(
      parseArgs("msd", { action: "connect", image: "rescue.iso" }),
      context as any,
    ));
  const d = getWrittenResources()[0].data;
  model.resources.msd.schema.parse(d);
  assertEquals(d.outcome, "dry-run");
  assertStringIncludes(String(d.message), "set_params");
  assertStringIncludes(String(d.message), "set_connected");
  assertEquals(fake.posts().length, 0);
});

Deno.test("msd connect apply selects the image, then attaches it", async () => {
  const fake = new FakeKvm(healthyRoutes({
    "GET /api/msd": MSD_WITH_IMAGE(false),
    "POST /api/msd/set_params": ok({}),
    "POST /api/msd/set_connected": ok({}),
  }));
  const { context } = ctx();
  await withFake(fake, () =>
    model.methods.msdChange.execute(
      parseArgs("msdChange", {
        action: "connect",
        image: "rescue.iso",
        cdrom: false,
      }),
      context as any,
    ));
  assertEquals(fake.posts().map((p) => [p.path, p.query]), [
    ["/api/msd/set_params", { image: "rescue.iso", cdrom: "0" }],
    ["/api/msd/set_connected", { connected: "1" }],
  ]);
});

Deno.test("msd waits for the device to drop a removed image before recording", async () => {
  // kvmd applies storage changes asynchronously; the first read after a
  // remove still lists the image. Seen live on firmware V1.9.1.
  let removed = false, readsAfter = 0;
  const fake = new FakeKvm(healthyRoutes({
    "GET /api/msd": () => {
      if (removed) readsAfter++;
      const gone = removed && readsAfter > 2;
      return MSD_WITH_IMAGE(false)().json && {
        json: {
          ok: true,
          result: {
            enabled: true,
            busy: false,
            drive: { connected: false, cdrom: true, image: null },
            storage: {
              images: gone ? {} : { "rescue.iso": { size: 10 } },
              parts: { "": { free: 1000 } },
            },
          },
        },
      };
    },
    "POST /api/msd/remove":
      () => ((removed = true), { json: { ok: true, result: {} } }),
  }));
  const { context, getWrittenResources } = ctx();
  await withFake(fake, () =>
    model.methods.msdChange.execute(
      parseArgs("msdChange", { action: "remove", image: "rescue.iso" }),
      context as any,
    ));
  const d = getWrittenResources()[0].data;
  assertEquals(d.images, []);
  assert(!String(d.message).includes("not yet updated"));
  assertEquals(readsAfter, 3);
});

Deno.test("msd records, without failing, a change the device never shows", async () => {
  const fake = new FakeKvm(healthyRoutes({
    "GET /api/msd": MSD_WITH_IMAGE(false),
    "POST /api/msd/remove": ok({}),
  }));
  const { context, getWrittenResources } = ctx();
  await withFake(fake, () =>
    model.methods.msdChange.execute(
      parseArgs("msdChange", { action: "remove", image: "rescue.iso" }),
      context as any,
    ));
  assertStringIncludes(
    String(getWrittenResources()[0].data.message),
    "not yet updated",
  );
});

Deno.test("driveInvisible only claims invisibility when the gadget says so", () => {
  assertEquals(driveInvisible({ cdrom: false, flash: true }, true), true);
  assertEquals(driveInvisible({ cdrom: false, flash: true }, false), false);
  assertEquals(driveInvisible({ cdrom: null, flash: null }, true), false);
  assertEquals(driveInvisible({ cdrom: false, flash: false }, null), false);
});

Deno.test("msd refuses to connect a CD-ROM the gadget will not present", async () => {
  // Seen live: kvmd accepted the attach and reported connected=true, and the
  // target enumerated nothing but the keyboard/mouse composite device.
  const fake = new FakeKvm(healthyRoutes({
    "GET /api/msd": MSD_WITH_IMAGE(false),
    "GET /api/system/otg_functions": ok({
      start_cdrom: false,
      start_flash: false,
    }),
  }));
  const { context, getWrittenResources } = ctx();
  await assertRejects(
    () =>
      withFake(fake, () =>
        model.methods.msdChange.execute(
          parseArgs("msdChange", {
            action: "connect",
            image: "rescue.iso",
          }),
          context as any,
        )),
    Error,
    "start_cdrom=false",
  );
  const d = getWrittenResources()[0].data;
  model.resources.msd.schema.parse(d);
  assertEquals(d.outcome, "refused");
  assertEquals(d.gadgetCdrom, false);
  assertEquals(fake.posts().length, 0);
});

Deno.test("health does not warn about attached media the target cannot see", async () => {
  const fake = new FakeKvm(healthyRoutes({
    "GET /api/msd": MSD_WITH_IMAGE(true),
    "GET /api/system/otg_functions": ok({
      start_cdrom: false,
      start_flash: false,
    }),
    "GET /api/upgrade/compare": ok({ server_version: "V1.9.1 release1" }),
    "GET /api/upgrade/version": ok({
      model: "RM1PE",
      version: "V1.9.1 release1",
    }),
  }));
  const { context, getWrittenResources } = ctx();
  await withFake(
    fake,
    () => model.methods.health.execute(parseArgs("health", {}), context as any),
  );
  const d = getWrittenResources()[0].data;
  model.resources.health.schema.parse(d);
  const codes = (d.findings as any[]).map((f) => f.code);
  assert(codes.includes("virtual_media_not_presented"));
  assert(!codes.includes("virtual_media_attached"));
  assertEquals(d.verdict, "ok");
});

Deno.test("msd refuses to remove the image that is attached", async () => {
  const fake = new FakeKvm(
    healthyRoutes({ "GET /api/msd": MSD_WITH_IMAGE(true) }),
  );
  const { context, getWrittenResources } = ctx();
  await assertRejects(
    () =>
      withFake(fake, () =>
        model.methods.msdChange.execute(
          parseArgs("msdChange", {
            action: "remove",
            image: "rescue.iso",
          }),
          context as any,
        )),
    Error,
    "disconnect first",
  );
  assertEquals(getWrittenResources()[0].data.outcome, "refused");
  assertEquals(fake.posts().length, 0);
});

Deno.test("msd upload refuses a file that does not exist", async () => {
  const fake = new FakeKvm(healthyRoutes());
  const { context } = ctx();
  await assertRejects(
    () =>
      withFake(fake, () =>
        model.methods.msdChange.execute(
          parseArgs("msdChange", {
            action: "upload",
            image: "x.iso",
            file: "/nonexistent/x.iso",
          }),
          context as any,
        )),
    Error,
    "not a readable file",
  );
  assertEquals(fake.posts().length, 0);
});

// ---------------------------------------------------------------------------
// Tailscale
// ---------------------------------------------------------------------------

const TS_UP = {
  enabled: true,
  running: true,
  state: "Running",
  ip: "198.51.100.7",
};
const tsCodes = (f: HealthFacts) =>
  evaluateHealth(f).findings.filter((x) => x.code.startsWith("tailscale_"))
    .map((x) => `${x.severity} ${x.code}`);

Deno.test("Tailscale up and answering on its tailnet IP adds no finding", () => {
  assertEquals(
    tsCodes(facts({
      tailscale: TS_UP,
      tailnet: {
        ip: "198.51.100.7",
        reachable: true,
        sameDevice: true,
        error: null,
      },
    })),
    [],
  );
});

Deno.test("a node deleted from the tailnet still says Running; only the probe catches it", () => {
  const f = facts({
    tailscale: TS_UP,
    tailnet: {
      ip: "198.51.100.7",
      reachable: false,
      sameDevice: null,
      error: "curl exit 28",
    },
  });
  assertEquals(tsCodes(f), ["warn tailscale_unreachable"]);
  assertEquals(evaluateHealth(f).verdict, "warn");
});

Deno.test("a re-added node with a new IP warns and names both addresses", () => {
  const { findings } = evaluateHealth(facts({
    tailscale: { ...TS_UP, ip: "198.51.100.9" },
    tailnet: {
      ip: "198.51.100.7",
      reachable: false,
      sameDevice: null,
      error: null,
    },
  }));
  const changed = findings.find((x) => x.code === "tailscale_ip_changed")!;
  assertEquals(changed.severity, "warn");
  assertStringIncludes(changed.message, "198.51.100.9");
  assertStringIncludes(changed.message, "198.51.100.7");
});

Deno.test("Tailscale off is info unless a tailnetIp says it is relied on", () => {
  const off = { ...TS_UP, enabled: false, running: false, state: "Stopped" };
  assertEquals(tsCodes(facts({ tailscale: off })), ["info tailscale_disabled"]);
  assertEquals(
    tsCodes(facts({
      tailscale: off,
      tailnet: {
        ip: "198.51.100.7",
        reachable: false,
        sameDevice: null,
        error: null,
      },
    })),
    ["warn tailscale_disabled", "warn tailscale_unreachable"],
  );
});

Deno.test("enabled but stopped, or logged out, warns with the daemon's state", () => {
  assertEquals(
    tsCodes(facts({ tailscale: { ...TS_UP, running: false } })),
    ["warn tailscale_not_running"],
  );
  const { findings } = evaluateHealth(facts({
    tailscale: { ...TS_UP, state: "NeedsLogin" },
  }));
  assertStringIncludes(
    findings.find((x) => x.code === "tailscale_not_connected")!.message,
    "NeedsLogin",
  );
});

function tailscaleRoutes(
  over: Record<string, Route> = {},
): Record<string, Route> {
  return healthyRoutes({
    "GET /api/tailscale/config": ok({
      accept_dns: false,
      accept_routes: false,
      advertise_routes: "",
      enable: true,
      exit_node: false,
    }),
    "GET /api/tailscale/status": ok({ running: true }),
    "GET /api/tailscale/login_status": ok({
      ipv4: "198.51.100.7",
      ipv6: "",
      login_name: "someone@example.com",
      status: "Running",
    }),
    ...over,
  });
}

/** Global arguments of every transport the code under test created. */
const created: any[] = [];

async function withHosts<T>(
  fakes: Record<string, FakeKvm>,
  fn: () => Promise<T>,
): Promise<T> {
  const orig = transportFactory.create;
  created.length = 0;
  transportFactory.create = (g) => {
    created.push(g);
    const f = fakes[g.host];
    if (!f) throw new Error(`no fake for ${g.host}`);
    return f;
  };
  try {
    return await fn();
  } finally {
    transportFactory.create = orig;
  }
}

function tailnetCtx() {
  return createModelTestContext({
    globalArgs: model.globalArguments.parse({
      host: "192.0.2.10",
      password: "x",
      tailnetIp: "198.51.100.7",
    }),
  });
}

const CERT_A: CertInfo = { ...FACTORY_CERT, fingerprint: "AA:11" };
const CERT_B: CertInfo = { ...FACTORY_CERT, fingerprint: "BB:22" };

/** A kvmd on the tailnet IP: anonymous auth check answers its 401 envelope. */
function kvmdTailnet(cert: CertInfo = CERT_A): FakeKvm {
  return new FakeKvm({
    "GET /api/auth/check": () => ({
      status: 401,
      json: {
        ok: false,
        result: { error: "UnauthorizedError", error_msg: "Unauthorized" },
      },
    }),
  }, { cert });
}

Deno.test("health probes the tailnet IP and records Tailscale, using only read-only GETs", async () => {
  const lan = new FakeKvm(tailscaleRoutes(), { cert: CERT_A });
  const tailnet = kvmdTailnet();
  const { context, getWrittenResources } = tailnetCtx();
  await withHosts(
    { "192.0.2.10": lan, "198.51.100.7": tailnet },
    () => model.methods.health.execute(parseArgs("health", {}), context as any),
  );
  const [w] = getWrittenResources();
  model.resources.health.schema.parse(w.data);
  assertEquals(w.data.tailscale, {
    enabled: true,
    running: true,
    state: "Running",
    ip: "198.51.100.7",
    expectedIp: "198.51.100.7",
    tailnetReachable: true,
    tailnetSameDevice: true,
  });
  assertEquals(
    (w.data.findings as any[]).filter((f) => f.code.startsWith("tailscale_")),
    [],
  );
  // The pinned address may not be this KVM: never send it the password, and
  // never even hand the probe's transport one.
  assertEquals(tailnet.calls.map((c) => [c.method, c.path, c.anonymous]), [
    ["GET", "/api/auth/check", true],
  ]);
  const probeG = created.find((g) => g.host === "198.51.100.7");
  assertEquals([probeG.username, probeG.password], ["", ""]);
  assert(probeG.timeoutMs <= 10000);
  // GET /api/tailscale/login is NOT read-only: it starts a login.
  assert(!lan.calls.some((c) => c.path === "/api/tailscale/login"));
  assertEquals(lan.posts().length + tailnet.posts().length, 0);
});

Deno.test("health records an unanswered tailnet IP as tailscale_unreachable, not a throw", async () => {
  const lan = new FakeKvm(tailscaleRoutes());
  const tailnet = new FakeKvm({}, { unreachable: true });
  const { context, getWrittenResources } = tailnetCtx();
  await withHosts(
    { "192.0.2.10": lan, "198.51.100.7": tailnet },
    () => model.methods.health.execute(parseArgs("health", {}), context as any),
  );
  const [w] = getWrittenResources();
  model.resources.health.schema.parse(w.data);
  assertEquals(w.data.reachable, true);
  assertEquals((w.data.tailscale as any).tailnetReachable, false);
  const f = (w.data.findings as any[]).find((x) =>
    x.code === "tailscale_unreachable"
  );
  assertEquals(f.severity, "warn");
  assertStringIncludes(f.message, "Failed to connect");
});

Deno.test("firmware without a Tailscale API leaves tailscale null and adds no finding", async () => {
  const fake = new FakeKvm(healthyRoutes());
  const { context, getWrittenResources } = ctx();
  await withFake(
    fake,
    () => model.methods.health.execute(parseArgs("health", {}), context as any),
  );
  const [w] = getWrittenResources();
  model.resources.health.schema.parse(w.data);
  assertEquals(w.data.tailscale, null);
  assert(
    !(w.data.findings as any[]).some((f) => f.code.startsWith("tailscale_")),
  );
});

Deno.test("tailnetIp must be a valid IPv4 literal", () => {
  for (
    const bad of [
      "kvm1.example.com",
      "256.1.1.1",
      "198.51.100",
      "198.051.100.7",
    ]
  ) {
    assertThrows(
      () =>
        model.globalArguments.parse({
          host: "192.0.2.10",
          password: "x",
          tailnetIp: bad,
        }),
      Error,
      undefined,
      bad,
    );
  }
});

Deno.test("an anonymous request carries no credentials at all", () => {
  const cfg = curlConfig(G, "GET", "/", "/tmp/out", { anonymous: true });
  assert(!cfg.includes("X-KVMD"), cfg);
  assertStringIncludes(curlConfig(G, "GET", "/", "/tmp/out"), "X-KVMD-Passwd");
});

async function runTailnet(lan: FakeKvm, tailnet: FakeKvm) {
  const { context, getWrittenResources } = tailnetCtx();
  await withHosts(
    { "192.0.2.10": lan, "198.51.100.7": tailnet },
    () => model.methods.health.execute(parseArgs("health", {}), context as any),
  );
  const [w] = getWrittenResources();
  model.resources.health.schema.parse(w.data);
  return w.data as any;
}

const codesOf = (d: any) =>
  (d.findings as any[]).filter((f) => f.code.startsWith("tailscale_")).map((
    f,
  ) => f.code);

Deno.test("a stale pin answered by some other web server is tailscale_wrong_device, not healthy", async () => {
  const other = new FakeKvm({
    "GET /api/auth/check": () => ({
      raw: new TextEncoder().encode("<html>hello</html>"),
      type: "text/html",
    }),
  });
  const d = await runTailnet(
    new FakeKvm(tailscaleRoutes(), { cert: CERT_A }),
    other,
  );
  assertEquals(d.tailscale.tailnetReachable, true);
  assertEquals(d.tailscale.tailnetSameDevice, false);
  assertEquals(codesOf(d), ["tailscale_wrong_device"]);
  assertEquals(d.verdict, "warn");
});

Deno.test("a different kvmd on the tailnet IP (other certificate) is tailscale_wrong_device", async () => {
  const d = await runTailnet(
    new FakeKvm(tailscaleRoutes(), { cert: CERT_A }),
    kvmdTailnet(CERT_B),
  );
  assertEquals(d.tailscale.tailnetSameDevice, false);
  assertEquals(codesOf(d), ["tailscale_wrong_device"]);
});

Deno.test("an unjudgeable certificate leaves sameDevice null and raises nothing", async () => {
  const d = await runTailnet(
    new FakeKvm(tailscaleRoutes(), { cert: null }),
    kvmdTailnet(),
  );
  assertEquals(d.tailscale.tailnetReachable, true);
  assertEquals(d.tailscale.tailnetSameDevice, null);
  assertEquals(codesOf(d), []);
});

Deno.test("tailnetIp on firmware without a Tailscale API records the probe with null device fields", async () => {
  const d = await runTailnet(
    new FakeKvm(healthyRoutes(), { cert: CERT_A }),
    kvmdTailnet(),
  );
  assertEquals(d.tailscale, {
    enabled: null,
    running: null,
    state: null,
    ip: null,
    expectedIp: "198.51.100.7",
    tailnetReachable: true,
    tailnetSameDevice: true,
  });
});

Deno.test("a Tailscale endpoint error is logged, not read as 'no API', and non-string fields are dropped", async () => {
  const lan = new FakeKvm(
    tailscaleRoutes({
      "GET /api/tailscale/status": () => ({ status: 500, json: { ok: false } }),
      "GET /api/tailscale/login_status": ok({
        ipv4: ["198.51.100.7"],
        status: 7,
      }),
    }),
    { cert: CERT_A },
  );
  const { context, getWrittenResources, getLogs } = tailnetCtx() as any;
  await withHosts(
    { "192.0.2.10": lan, "198.51.100.7": kvmdTailnet() },
    () => model.methods.health.execute(parseArgs("health", {}), context as any),
  );
  const [w] = getWrittenResources();
  model.resources.health.schema.parse(w.data);
  const ts = (w.data as any).tailscale;
  assertEquals([ts.running, ts.state, ts.ip], [null, null, null]);
  assert(!codesOf(w.data).includes("tailscale_ip_changed"));
  assert(
    JSON.stringify(getLogs()).includes("/api/tailscale/status"),
    "the failure must be logged",
  );
});

Deno.test("curl config skips proxies, and an anonymous request carries no credentials", () => {
  const cfg = curlConfig(G, "GET", "/", "/tmp/out");
  assertStringIncludes(cfg, 'noproxy = "*"');
  const anon = curlConfig(G, "GET", "/", "/tmp/out", { anonymous: true });
  assert(!anon.includes("X-KVMD"), anon);
  assertStringIncludes(anon, 'noproxy = "*"');
});

Deno.test("redactUrl strips userinfo and signed queries from a download URL", () => {
  assertEquals(
    redactUrl("https://u:p@iso.example.com/a/b.iso?X-Amz-Signature=s#f"),
    "https://iso.example.com/a/b.iso (redacted)",
  );
  assertEquals(
    redactUrl("https://iso.example.com/b.iso"),
    "https://iso.example.com/b.iso",
  );
  assertEquals(redactUrl("not a url"), "(unparseable URL)");
});

Deno.test("msd download never records or logs the credentials in its URL", async () => {
  const fake = new FakeKvm(healthyRoutes());
  const { context, getWrittenResources } = ctx();
  await withFake(
    fake,
    () =>
      model.methods.msd.execute(
        parseArgs("msd", {
          action: "download",
          image: "x.iso",
          url: "https://u:secretpw@iso.example.com/x.iso?sig=abc",
        }),
        context as any,
      ),
  );
  const [w] = getWrittenResources();
  assert(!JSON.stringify(w.data).includes("secretpw"));
  assert(!JSON.stringify(w.data).includes("sig=abc"));
  assertEquals(w.data.outcome, "dry-run");
});

Deno.test("msd disconnect with nothing attached, and remove of a missing image, succeed as no-ops", async () => {
  for (
    const args of [
      { action: "disconnect" },
      { action: "remove", image: "gone.iso" },
    ]
  ) {
    const fake = new FakeKvm(healthyRoutes());
    const { context, getWrittenResources } = ctx();
    await withFake(
      fake,
      () =>
        model.methods.msdChange.execute(
          parseArgs("msdChange", args),
          context as any,
        ),
    );
    const [w] = getWrittenResources();
    model.resources.msd.schema.parse(w.data);
    assertEquals(w.data.outcome, "done");
    assertEquals(w.data.applied, false);
    assertEquals(fake.posts().length, 0, `${args.action} must not POST`);
  }
});

Deno.test("CliTransport ignores ~/.curlrc, so a 'verbose' there cannot print the password", async () => {
  // A local TLS server that sends headers and then stalls, so curl times out
  // and its stderr is surfaced in the error, as it would be from a real KVM.
  const dir = await Deno.makeTempDir();
  const oldHome = Deno.env.get("HOME");
  const oldCurlHome = Deno.env.get("CURL_HOME");
  try {
    const gen = await new Deno.Command("openssl", {
      args: [
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-subj",
        "/CN=localhost",
        "-days",
        "1",
        "-keyout",
        `${dir}/key.pem`,
        "-out",
        `${dir}/cert.pem`,
      ],
      stdout: "null",
      stderr: "null",
    }).output();
    assert(gen.success, "openssl could not make a test certificate");
    await Deno.writeTextFile(`${dir}/.curlrc`, "verbose\n");
    Deno.env.set("HOME", dir);
    Deno.env.set("CURL_HOME", dir);
    const server = Deno.listenTls({
      hostname: "127.0.0.1",
      port: 0,
      cert: await Deno.readTextFile(`${dir}/cert.pem`),
      key: await Deno.readTextFile(`${dir}/key.pem`),
    });
    const port = (server.addr as Deno.NetAddr).port;
    const held: Deno.Conn[] = [];
    (async () => {
      for await (const c of server) held.push(c); // accept, never answer
    })().catch(() => {});
    try {
      const t = new CliTransport(model.globalArguments.parse({
        host: "127.0.0.1",
        port,
        password: "pw-must-not-leak",
        timeoutMs: 1000,
      }));
      const e = await assertRejects(() => t.request("GET", "/api/auth/check"));
      assert(
        !(e as Error).message.includes("pw-must-not-leak"),
        (e as Error).message,
      );
      assert(!(e as Error).message.includes("X-KVMD-Passwd"));
    } finally {
      server.close();
      for (const c of held) c.close();
    }
  } finally {
    oldHome === undefined
      ? Deno.env.delete("HOME")
      : Deno.env.set("HOME", oldHome);
    oldCurlHome === undefined
      ? Deno.env.delete("CURL_HOME")
      : Deno.env.set("CURL_HOME", oldCurlHome);
    await Deno.remove(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// 2026.10.19.1: reads and writes split; labeled pre-flight checks
// ---------------------------------------------------------------------------

Deno.test("atx and msd refuse apply: true loudly, before any request", async () => {
  for (
    const [m, a] of [
      ["atx", { action: "click_reset", apply: true }],
      ["msd", { action: "remove", image: "rescue.iso", apply: true }],
    ] as const
  ) {
    const fake = new FakeKvm(healthyRoutes({ "GET /api/atx": ATX_BOARD }));
    const { context, getWrittenResources } = ctx();
    await assertRejects(
      () =>
        withFake(
          fake,
          () =>
            (model.methods[m].execute as any)(parseArgs(m, a), context as any),
        ),
      Error,
      m === "atx" ? "atxPress" : "msdChange",
    );
    assertEquals(fake.calls.length, 0, m);
    assertEquals(getWrittenResources().length, 0, m);
  }
});

Deno.test("the write methods take no apply and no status action", () => {
  for (const m of ["atxPress", "msdChange"] as const) {
    const shape = model.methods[m].arguments.shape as Record<string, any>;
    assert(!("apply" in shape), m);
    assert(!shape.action.safeParse("status").success, m);
  }
});

Deno.test("plans point at the write method", async () => {
  const fake = new FakeKvm(healthyRoutes({ "GET /api/atx": ATX_BOARD }));
  const { context, getWrittenResources } = ctx();
  await withFake(
    fake,
    () =>
      model.methods.atx.execute(
        parseArgs("atx", { action: "off" }),
        context as any,
      ),
  );
  assertStringIncludes(
    String(getWrittenResources()[0].data.message),
    "call atxPress",
  );
});

Deno.test("every check is labeled live and scoped to its write method only", () => {
  const scope: Record<string, string[]> = {
    "atx-board-present": ["atxPress"],
    "atx-not-busy": ["atxPress"],
    "msd-enabled": ["msdChange"],
    "msd-not-busy": ["msdChange"],
  };
  assertEquals(Object.keys(model.checks).sort(), Object.keys(scope).sort());
  for (const [n, c] of Object.entries(model.checks)) {
    // An unscoped swamp check runs before EVERY method, health included.
    assertEquals(c.appliesTo, scope[n], n);
    assert(c.labels.includes("live"), n);
  }
});

const runCheck = async (name: keyof typeof model.checks, fake: FakeKvm) => {
  checkReadCache.clear();
  return await withFake(fake, () =>
    model.checks[name].execute({
      globalArgs: { host: "192.0.2.10", password: "x" },
    }));
};

Deno.test("checks pass on a ready device, and checks of one endpoint share one read", async () => {
  const fake = new FakeKvm(healthyRoutes({ "GET /api/atx": ATX_BOARD }));
  checkReadCache.clear();
  for (
    const n of [
      "atx-board-present",
      "atx-not-busy",
      "msd-enabled",
      "msd-not-busy",
    ] as const
  ) {
    const r = await withFake(
      fake,
      () =>
        model.checks[n].execute({
          globalArgs: { host: "192.0.2.10", password: "x" },
        }),
    );
    assertEquals(r, { pass: true }, n);
  }
  assertEquals(fake.calls.map((c) => c.path), ["/api/atx", "/api/msd"]);
});

Deno.test("each check fails on its own condition, with the method's wording", async () => {
  const cases = [
    ["atx-board-present", {
      "GET /api/atx": ok({ enabled: false, busy: false }),
    }, "no ATX board"],
    [
      "atx-not-busy",
      { "GET /api/atx": ok({ enabled: true, busy: true }) },
      "already in progress",
    ],
    [
      "msd-enabled",
      { "GET /api/msd": ok({ enabled: false, busy: false }) },
      "disabled",
    ],
    [
      "msd-not-busy",
      { "GET /api/msd": ok({ enabled: true, busy: true }) },
      "already in progress",
    ],
  ] as const;
  for (const [n, routes, msg] of cases) {
    const r = await runCheck(n, new FakeKvm(healthyRoutes(routes)));
    assertEquals(r.pass, false, n);
    assertStringIncludes(r.errors![0], msg, n);
  }
});

Deno.test("a check fails closed when its read fails, and the failure is not cached", async () => {
  const r = await runCheck(
    "atx-board-present",
    new FakeKvm(healthyRoutes(), { unreachable: true }),
  );
  assertEquals(r.pass, false);
  assertStringIncludes(r.errors![0], "could not read /api/atx");
  await Promise.resolve();
  assertEquals(checkReadCache.entries.size, 0);
});

Deno.test("the inline guard still refuses when checks are skipped", async () => {
  // atxPress against a board that is busy: the method itself refuses.
  const fake = new FakeKvm(
    healthyRoutes({
      "GET /api/atx": ok({ enabled: true, busy: true, power: "on" }),
    }),
  );
  const { context } = ctx();
  await assertRejects(
    () =>
      withFake(
        fake,
        () =>
          model.methods.atxPress.execute(
            parseArgs("atxPress", { action: "click_reset" }),
            context as any,
          ),
      ),
    Error,
    "busy",
  );
  assertEquals(fake.posts().length, 0);
});
