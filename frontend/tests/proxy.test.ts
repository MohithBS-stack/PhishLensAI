/**
 * Automated Unit Tests for Next.js Same-Origin API Proxy.
 *
 * Verifies:
 * - Route/path mapping and query parameter handling.
 * - Path traversal and target override prevention.
 * - Cookie transformation: Domain stripping, SameSite=Lax enforcement, HttpOnly/Secure preservation.
 * - Logout cookie clearing behavior.
 * - Forwarding of GET, POST, Authorization headers, and bodies.
 * - Separate Set-Cookie preservation without malformed comma-merging.
 * - Upstream 504 timeout and 503 connection error handling.
 * - Rejection of unsupported HTTP methods (405).
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  resolveTargetUrl,
  transformSetCookie,
  validateCsrfProtection,
  handleProxyRequest,
  ALLOWED_METHODS,
  HOP_BY_HOP_HEADERS,
} from "../lib/proxy.ts";
import { resolveApiBaseUrl } from "../lib/api.ts";

describe("Proxy URL Resolution & Security", () => {
  const BACKEND_URL = "https://phishlens-ai-backend.onrender.com";

  it("should map valid path segments to the /api/v1/... prefix", () => {
    const res = resolveTargetUrl(BACKEND_URL, ["scan", "unified"], "");
    assert.equal(
      res.url,
      "https://phishlens-ai-backend.onrender.com/api/v1/scan/unified"
    );
    assert.equal(res.error, undefined);
  });

  it("should preserve query parameters correctly", () => {
    const res = resolveTargetUrl(
      BACKEND_URL,
      ["health"],
      "full=true&format=json"
    );
    assert.equal(
      res.url,
      "https://phishlens-ai-backend.onrender.com/api/v1/health?full=true&format=json"
    );
  });

  it("should strip trailing slashes from the backend base URL", () => {
    const res = resolveTargetUrl("http://localhost:8000///", ["auth", "login"], "");
    assert.equal(res.url, "http://localhost:8000/api/v1/auth/login");
  });

  it("should reject path traversal attempts with '..'", () => {
    const res = resolveTargetUrl(BACKEND_URL, ["auth", "..", "admin"], "");
    assert.equal(res.url, null);
    assert.match(res.error || "", /Invalid path segment/);
  });

  it("should reject path segments containing slashes or backslashes", () => {
    const res1 = resolveTargetUrl(BACKEND_URL, ["auth/extra"], "");
    assert.equal(res1.url, null);

    const res2 = resolveTargetUrl(BACKEND_URL, ["auth\\extra"], "");
    assert.equal(res2.url, null);
  });

  it("should confirm the backend target host cannot be overridden by client input", () => {
    const res = resolveTargetUrl(
      BACKEND_URL,
      ["evil.com", "api"],
      "target=http://malicious.site"
    );
    // The target host is strictly the fixed BACKEND_URL; evil.com is just a path segment
    assert.ok(res.url?.startsWith("https://phishlens-ai-backend.onrender.com/api/v1/"));
    assert.ok(!res.url?.startsWith("https://evil.com"));
  });
});

describe("Cookie Transformation & Sanitation", () => {
  it("should strip Domain attribute so cookie scopes to the browser-facing origin (host-only)", () => {
    const raw =
      "phishlens_refresh_token=sec_tok_123; Path=/api/v1/auth; Domain=phishlens-ai-backend.onrender.com; HttpOnly; SameSite=none; Secure";
    const transformed = transformSetCookie(raw);

    assert.ok(!transformed.toLowerCase().includes("domain="));
    assert.ok(transformed.includes("phishlens_refresh_token=sec_tok_123"));
    assert.ok(transformed.includes("Path=/api/v1/auth"));
  });

  it("should normalize SameSite to Lax for first-party browser navigation", () => {
    const raw =
      "phishlens_refresh_token=sec_tok_123; Path=/api/v1/auth; SameSite=None; Secure; HttpOnly";
    const transformed = transformSetCookie(raw);

    assert.ok(transformed.includes("SameSite=Lax"));
    assert.ok(!transformed.includes("SameSite=None"));
  });

  it("should preserve logout clearing attributes (Max-Age=0, empty value)", () => {
    const raw =
      'phishlens_refresh_token=""; Path=/api/v1/auth; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Domain=onrender.com; HttpOnly; SameSite=lax';
    const transformed = transformSetCookie(raw);

    assert.ok(transformed.includes('phishlens_refresh_token=""'));
    assert.ok(transformed.includes("Max-Age=0"));
    assert.ok(transformed.includes("Path=/api/v1/auth"));
    assert.ok(!transformed.toLowerCase().includes("domain="));
    assert.ok(transformed.includes("SameSite=Lax"));
  });

  it("should ensure HttpOnly is always added if missing", () => {
    const raw = "test_cookie=abc; Path=/api/v1/auth";
    const transformed = transformSetCookie(raw);
    assert.ok(transformed.includes("HttpOnly"));
  });
});

describe("HTTP Method Filtering & Hop-by-Hop Headers", () => {
  it("should reject unsupported HTTP methods with 405 Method Not Allowed", async () => {
    const putReq = new Request("http://localhost:3000/api/v1/auth/login", {
      method: "PUT",
    });
    const res = await handleProxyRequest(putReq, ["auth", "login"]);
    assert.equal(res.status, 405);
    assert.equal(res.headers.get("Allow"), "GET, POST, OPTIONS");
    const json = await res.json();
    assert.equal(json.error.code, "METHOD_NOT_ALLOWED");
  });

  it("should respond to OPTIONS preflight requests with 204", async () => {
    const optReq = new Request("http://localhost:3000/api/v1/scan/unified", {
      method: "OPTIONS",
    });
    const res = await handleProxyRequest(optReq, ["scan", "unified"]);
    assert.equal(res.status, 204);
    assert.ok(res.headers.get("Allow")?.includes("OPTIONS"));
  });

  it("should define the correct hop-by-hop headers to filter", () => {
    assert.ok(HOP_BY_HOP_HEADERS.has("connection"));
    assert.ok(HOP_BY_HOP_HEADERS.has("transfer-encoding"));
    assert.ok(HOP_BY_HOP_HEADERS.has("upgrade"));
    assert.ok(HOP_BY_HOP_HEADERS.has("host"));
  });
});

describe("Proxy Request Execution & Mocked Upstream", () => {
  const originalFetch = globalThis.fetch;

  it("should forward POST request body and Authorization header, preserving upstream response", async () => {
    let capturedUrl = "";
    let capturedMethod = "";
    let capturedAuth = "";
    let capturedBody = "";

    globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      capturedUrl = url.toString();
      capturedMethod = init?.method || "";
      capturedAuth = new Headers(init?.headers).get("authorization") || "";
      capturedBody = init?.body ? Buffer.from(init.body as ArrayBuffer).toString() : "";

      return new Response(JSON.stringify({ verdict: "benign", score: 5.0 }), {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "X-Request-ID": "req-proxy-test-123",
        },
      });
    }) as typeof fetch;

    try {
      const clientReq = new Request("http://localhost:3000/api/v1/scan/unified", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer test-jwt-token-abc",
        },
        body: JSON.stringify({ text: "Hello security check" }),
      });

      const res = await handleProxyRequest(clientReq, ["scan", "unified"]);
      assert.equal(res.status, 200);
      assert.equal(res.headers.get("X-Request-ID"), "req-proxy-test-123");

      const resJson = await res.json();
      assert.equal(resJson.verdict, "benign");
      assert.equal(resJson.score, 5.0);

      assert.ok(capturedUrl.includes("/api/v1/scan/unified"));
      assert.equal(capturedMethod, "POST");
      assert.equal(capturedAuth, "Bearer test-jwt-token-abc");
      assert.ok(capturedBody.includes("Hello security check"));
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("should preserve separate Set-Cookie headers without merging them", async () => {
    globalThis.fetch = (async () => {
      const headers = new Headers();
      headers.append(
        "Set-Cookie",
        "phishlens_refresh_token=token_xyz; Path=/api/v1/auth; Domain=onrender.com; HttpOnly; SameSite=none; Secure"
      );
      headers.append(
        "Set-Cookie",
        "session_hint=active; Path=/; HttpOnly; SameSite=lax"
      );

      return new Response(JSON.stringify({ status: "ok" }), {
        status: 200,
        headers,
      });
    }) as typeof fetch;

    try {
      const clientReq = new Request("http://localhost:3000/api/v1/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "test@example.com", password: "Pass!" }),
      });

      const res = await handleProxyRequest(clientReq, ["auth", "login"]);
      assert.equal(res.status, 200);

      // Verify separate Set-Cookie headers
      const setCookies = (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie
        ? (res.headers as unknown as { getSetCookie: () => string[] }).getSetCookie()
        : [res.headers.get("set-cookie") || ""];

      assert.equal(setCookies.length, 2);
      assert.ok(setCookies[0].includes("phishlens_refresh_token=token_xyz"));
      assert.ok(!setCookies[0].toLowerCase().includes("domain="));
      assert.ok(setCookies[0].includes("SameSite=Lax"));
      assert.ok(setCookies[1].includes("session_hint=active"));
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("should return HTTP 504 on upstream timeout", async () => {
    globalThis.fetch = (async () => {
      const err = new DOMException("The operation was aborted", "AbortError");
      throw err;
    }) as typeof fetch;

    try {
      const clientReq = new Request("http://localhost:3000/api/v1/scan/unified", {
        method: "POST",
      });

      const res = await handleProxyRequest(clientReq, ["scan", "unified"]);
      assert.equal(res.status, 504);
      const json = await res.json();
      assert.equal(json.error.code, "UPSTREAM_TIMEOUT");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("should return HTTP 503 when upstream backend is unreachable", async () => {
    globalThis.fetch = (async () => {
      throw new Error("ECONNREFUSED 127.0.0.1:8000");
    }) as typeof fetch;

    try {
      const clientReq = new Request("http://localhost:3000/api/v1/health", {
        method: "GET",
      });

      const res = await handleProxyRequest(clientReq, ["health"]);
      assert.equal(res.status, 503);
      const json = await res.json();
      assert.equal(json.error.code, "BACKEND_UNAVAILABLE");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe("CSRF Defense & Origin Verification", () => {
  it("should permit safe HTTP methods (GET, HEAD, OPTIONS) without Origin", () => {
    const getReq = new Request("http://localhost:3000/api/v1/health", { method: "GET" });
    assert.equal(validateCsrfProtection(getReq).valid, true);

    const headReq = new Request("http://localhost:3000/api/v1/health", { method: "HEAD" });
    assert.equal(validateCsrfProtection(headReq).valid, true);

    const optReq = new Request("http://localhost:3000/api/v1/health", { method: "OPTIONS" });
    assert.equal(validateCsrfProtection(optReq).valid, true);
  });

  it("should reject cross-site state-changing requests when Sec-Fetch-Site is cross-site", () => {
    const req = new Request("http://localhost:3000/api/v1/auth/refresh", {
      method: "POST",
      headers: {
        "Sec-Fetch-Site": "cross-site",
        Origin: "https://evil-attacker.com",
      },
    });
    const res = validateCsrfProtection(req);
    assert.equal(res.valid, false);
    assert.match(res.reason || "", /Sec-Fetch-Site policy/);
  });

  it("should permit legitimate same-origin requests matching the Host header", () => {
    const req = new Request("https://phishlens-ai.vercel.app/api/v1/auth/refresh", {
      method: "POST",
      headers: {
        Host: "phishlens-ai.vercel.app",
        Origin: "https://phishlens-ai.vercel.app",
      },
    });
    assert.equal(validateCsrfProtection(req).valid, true);
  });

  it("should permit localhost development same-origin requests", () => {
    const req = new Request("http://localhost:3000/api/v1/scan/unified", {
      method: "POST",
      headers: {
        Host: "localhost:3000",
        Origin: "http://localhost:3000",
      },
    });
    assert.equal(validateCsrfProtection(req).valid, true);
  });

  it("should permit explicitly configured allowed origins", () => {
    const req = new Request("https://phishlens-ai.vercel.app/api/v1/auth/refresh", {
      method: "POST",
      headers: {
        Host: "phishlens-ai.vercel.app",
        Origin: "https://phishlens-ai-preview-staging.vercel.app",
      },
    });
    const res = validateCsrfProtection(req, ["https://phishlens-ai-preview-staging.vercel.app"]);
    assert.equal(res.valid, true);
  });

  it("should reject attacker-controlled arbitrary Vercel subdomains", () => {
    const req = new Request("https://phishlens-ai.vercel.app/api/v1/auth/refresh", {
      method: "POST",
      headers: {
        Host: "phishlens-ai.vercel.app",
        Origin: "https://phishlens-ai-attacker.vercel.app",
      },
    });
    const res = validateCsrfProtection(req);
    assert.equal(res.valid, false);
    assert.match(res.reason || "", /Untrusted cross-origin request/);
  });

  it("should reject client manipulation of X-Forwarded-Host header", () => {
    // Attacker sends X-Forwarded-Host: evil.com attempting to match Origin: https://evil.com
    const req = new Request("https://phishlens-ai.vercel.app/api/v1/auth/refresh", {
      method: "POST",
      headers: {
        Host: "phishlens-ai.vercel.app",
        "X-Forwarded-Host": "evil.com",
        Origin: "https://evil.com",
      },
    });
    const res = validateCsrfProtection(req);
    assert.equal(res.valid, false);
    assert.match(res.reason || "", /Untrusted cross-origin request/);
  });

  it("should reject opaque null origin (from sandboxed iframes or data URIs)", () => {
    const req = new Request("https://phishlens-ai.vercel.app/api/v1/auth/refresh", {
      method: "POST",
      headers: {
        Host: "phishlens-ai.vercel.app",
        Origin: "null",
      },
    });
    const res = validateCsrfProtection(req);
    assert.equal(res.valid, false);
    assert.match(res.reason || "", /Opaque or null origin rejected/);
  });

  it("should reject unauthorized cross-origin POST requests", () => {
    const req = new Request("https://phishlens-ai.vercel.app/api/v1/auth/refresh", {
      method: "POST",
      headers: {
        Host: "phishlens-ai.vercel.app",
        Origin: "https://hostile-phishing-attacker.com",
      },
    });
    const res = validateCsrfProtection(req);
    assert.equal(res.valid, false);
    assert.match(res.reason || "", /Untrusted cross-origin request/);
  });

  it("should reject unauthorized cross-origin Referer headers when Origin is absent", () => {
    const req = new Request("https://phishlens-ai.vercel.app/api/v1/auth/refresh", {
      method: "POST",
      headers: {
        Host: "phishlens-ai.vercel.app",
        Referer: "https://evil-phishing-origin.com/attack-page.html",
      },
    });
    const res = validateCsrfProtection(req);
    assert.equal(res.valid, false);
    assert.match(res.reason || "", /Untrusted cross-origin referer/);
  });

  it("should reject cookie-authenticated state-changing POST requests lacking both Origin and Referer", () => {
    const req = new Request("https://phishlens-ai.vercel.app/api/v1/auth/refresh", {
      method: "POST",
      headers: {
        Cookie: "phishlens_refresh_token=sample_token_xyz",
      },
    });
    const res = validateCsrfProtection(req);
    assert.equal(res.valid, false);
    assert.match(res.reason || "", /Cookie-authenticated state-changing requests require an Origin or Referer/);
  });

  it("should block cross-origin requests through handleProxyRequest with HTTP 403", async () => {
    const clientReq = new Request("http://localhost:3000/api/v1/auth/refresh", {
      method: "POST",
      headers: {
        Host: "localhost:3000",
        Origin: "https://malicious-site.com",
      },
    });
    const res = await handleProxyRequest(clientReq, ["auth", "refresh"]);
    assert.equal(res.status, 403);
    const json = await res.json();
    assert.equal(json.error.code, "CROSS_SITE_REQUEST_FORBIDDEN");
  });
});

describe("Accidental Proxy Bypass Prevention (resolveApiBaseUrl)", () => {
  it("should strictly enforce relative URL in production browser even if NEXT_PUBLIC_API_URL is configured", () => {
    const resolved = resolveApiBaseUrl(
      "https://phishlens-ai-backend.onrender.com",
      /* isProduction */ true,
      /* isBrowser */ true
    );
    assert.equal(resolved, "");
  });

  it("should allow explicit backend URL in local development for debugging", () => {
    const resolved = resolveApiBaseUrl(
      "http://localhost:8000",
      /* isProduction */ false,
      /* isBrowser */ true
    );
    assert.equal(resolved, "http://localhost:8000");
  });

  it("should default to relative URL in development when NEXT_PUBLIC_API_URL is empty", () => {
    const resolved = resolveApiBaseUrl(
      "",
      /* isProduction */ false,
      /* isBrowser */ true
    );
    assert.equal(resolved, "");
  });

  it("should preserve configured URL on server-side (SSR) in production if required", () => {
    const resolved = resolveApiBaseUrl(
      "http://localhost:8000",
      /* isProduction */ true,
      /* isBrowser */ false
    );
    assert.equal(resolved, "http://localhost:8000");
  });
});
