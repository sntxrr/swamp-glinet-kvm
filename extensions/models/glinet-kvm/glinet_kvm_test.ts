// Tests hand the scripted context to execute() as `any`, as sibling extensions do.
// deno-lint-ignore-file no-explicit-any
import {
  assert,
  assertEquals,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20260928.39";
import {
  type CertInfo,
  certMatchesHost,
  curlConfig,
  curlQuote,
  driveInvisible,
  evaluateHealth,
  type HealthFacts,
  type HttpResult,
  model,
  msdSettle,
  parseCertText,
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
  calls: { method: string; path: string; query: Record<string, string> }[] = [];
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
    this.calls.push({ method, path, query });
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
        model.methods.atx.execute(
          parseArgs("atx", { action: "reset_hard", apply: true }),
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
    model.methods.atx.execute(
      parseArgs("atx", { action: "click_reset", apply: true }),
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
    model.methods.msd.execute(
      parseArgs("msd", {
        action: "connect",
        image: "rescue.iso",
        cdrom: false,
        apply: true,
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
    model.methods.msd.execute(
      parseArgs("msd", { action: "remove", image: "rescue.iso", apply: true }),
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
    model.methods.msd.execute(
      parseArgs("msd", { action: "remove", image: "rescue.iso", apply: true }),
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
        model.methods.msd.execute(
          parseArgs("msd", {
            action: "connect",
            image: "rescue.iso",
            apply: true,
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
        model.methods.msd.execute(
          parseArgs("msd", {
            action: "remove",
            image: "rescue.iso",
            apply: true,
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
        model.methods.msd.execute(
          parseArgs("msd", {
            action: "upload",
            image: "x.iso",
            file: "/nonexistent/x.iso",
            apply: true,
          }),
          context as any,
        )),
    Error,
    "not a readable file",
  );
  assertEquals(fake.posts().length, 0);
});
