/**
 * Server-side Same-Origin API Proxy Logic for PhishLens AI.
 *
 * Forwards browser requests from Next.js (/api/v1/...) to the internal FastAPI backend
 * while preserving cookies, security headers, and preventing open-proxy misuse.
 */

export const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
]);

export const ALLOWED_METHODS = new Set(["GET", "POST", "OPTIONS"]);

/**
 * Resolves and sanitizes the target backend URL.
 * Strictly prevents open-proxy behavior by hardcoding the server-side backend origin.
 */
export function resolveTargetUrl(
  backendBaseUrl: string,
  pathSegments: string[],
  searchString: string = ""
): { url: string | null; error?: string } {
  if (!backendBaseUrl || typeof backendBaseUrl !== "string") {
    return { url: null, error: "Backend base URL is not configured." };
  }

  if (!pathSegments || pathSegments.length === 0) {
    return { url: null, error: "Empty path segments." };
  }

  for (const seg of pathSegments) {
    if (
      seg === ".." ||
      seg === "." ||
      seg.includes("/") ||
      seg.includes("\\") ||
      seg.includes("%2f") ||
      seg.includes("%2F")
    ) {
      return { url: null, error: "Invalid path segment detected." };
    }
  }

  const cleanBase = backendBaseUrl.trim().replace(/\/+$/, "");
  const sanitizedPath = pathSegments.map((s) => encodeURIComponent(s)).join("/");
  const cleanSearch = searchString
    ? searchString.startsWith("?")
      ? searchString
      : `?${searchString}`
    : "";

  return { url: `${cleanBase}/api/v1/${sanitizedPath}${cleanSearch}` };
}

/**
 * Transforms backend Set-Cookie headers so they safely bind to the browser-facing origin.
 * - Strips `Domain=...` to ensure a host-only cookie on the frontend origin.
 * - Enforces `SameSite=Lax` for first-party browser navigation security.
 * - Ensures `HttpOnly` and `Secure` attributes are retained.
 */
export function transformSetCookie(setCookieStr: string): string {
  if (!setCookieStr || typeof setCookieStr !== "string") {
    return "";
  }

  const parts = setCookieStr.split(";").map((p) => p.trim());
  const transformed: string[] = [];

  for (const part of parts) {
    const lower = part.toLowerCase();

    // 1. Strip Domain attribute to keep cookie scoped strictly to the frontend origin
    if (lower.startsWith("domain=")) {
      continue;
    }

    // 2. Normalize SameSite to Lax for same-origin browser interactions
    if (lower.startsWith("samesite=")) {
      transformed.push("SameSite=Lax");
      continue;
    }

    transformed.push(part);
  }

  // Ensure security attributes
  const lowerAll = transformed.map((p) => p.toLowerCase());
  if (!lowerAll.includes("httponly")) {
    transformed.push("HttpOnly");
  }
  if (!lowerAll.includes("secure") && process.env.NODE_ENV === "production") {
    transformed.push("Secure");
  }
  if (!lowerAll.some((p) => p.startsWith("samesite="))) {
    transformed.push("SameSite=Lax");
  }

  return transformed.join("; ");
}

/**
 * Validates CSRF defense on state-changing requests.
 *
 * Hardened Security Invariants:
 * 1. Safe methods (GET, HEAD, OPTIONS) do not change state and are allowed.
 * 2. Rejects if browser supplies `Sec-Fetch-Site: cross-site`.
 * 3. Never trusts client-supplied `X-Forwarded-Host` or `X-Forwarded-Proto` for origin matching.
 *    Relies strictly on `new URL(request.url).host` (the server's verified host).
 * 4. Rejects `Origin: null` (opaque origins from sandboxed iframes or data URIs).
 * 5. Uses strict exact matching for allowed origins (`https://phishlens-ai.vercel.app`,
 *    `http://localhost:3000`, `http://127.0.0.1:3000`, and explicitly configured `ALLOWED_ORIGINS`).
 *    Does NOT use permissive prefix wildcards that would allow attacker-registered Vercel subdomains.
 * 6. Validates both `Origin` and `Referer` when present.
 * 7. Rejects cookie-authenticated requests lacking both Origin and Referer.
 */
export function validateCsrfProtection(
  request: Request,
  customAllowedOrigins: string[] = []
): { valid: boolean; reason?: string } {
  const method = request.method.toUpperCase();
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") {
    return { valid: true };
  }

  // 1. Browser-enforced Sec-Fetch-Site metadata
  const secFetchSite = request.headers.get("sec-fetch-site")?.toLowerCase();
  if (secFetchSite === "cross-site") {
    return {
      valid: false,
      reason: "Cross-site request blocked by Sec-Fetch-Site policy.",
    };
  }

  // 2. Determine verified server host (never trust unverified client-supplied X-Forwarded-Host)
  let serverHost = "";
  try {
    serverHost = new URL(request.url).host.toLowerCase().trim();
  } catch {
    serverHost = (request.headers.get("host") || "").toLowerCase().trim();
  }

  // Whitelist of trusted origins
  const envAllowedOrigins = (process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((o) => o.trim().toLowerCase())
    .filter(Boolean);

  const allowedOriginsSet = new Set([
    "https://phishlens-ai.vercel.app",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    ...envAllowedOrigins,
    ...customAllowedOrigins.map((o) => o.toLowerCase().trim()),
  ]);

  const origin = request.headers.get("origin")?.trim();
  const referer = request.headers.get("referer")?.trim();

  // Helper: check if a given origin URL is trusted
  const isTrustedOrigin = (parsedOrigin: URL): boolean => {
    const originHost = parsedOrigin.host.toLowerCase();
    const originStr = parsedOrigin.origin.toLowerCase();

    // Matches verified server host (same-origin)
    if (serverHost && originHost === serverHost) {
      return true;
    }

    // Matches explicit authorized origin whitelist
    if (allowedOriginsSet.has(originStr)) {
      return true;
    }

    return false;
  };

  // 3. Validate Origin header
  if (origin) {
    if (origin.toLowerCase() === "null" || origin.toLowerCase() === "undefined") {
      return {
        valid: false,
        reason: "Opaque or null origin rejected on state-changing request.",
      };
    }

    let originUrl: URL;
    try {
      originUrl = new URL(origin);
    } catch {
      return { valid: false, reason: "Malformed Origin header." };
    }

    if (!isTrustedOrigin(originUrl)) {
      return {
        valid: false,
        reason: `Untrusted cross-origin request from '${origin}'.`,
      };
    }
  }

  // 4. Validate Referer header if present
  if (referer) {
    let refererUrl: URL;
    try {
      refererUrl = new URL(referer);
    } catch {
      return { valid: false, reason: "Malformed Referer header." };
    }

    if (!isTrustedOrigin(refererUrl)) {
      return {
        valid: false,
        reason: `Untrusted cross-origin referer '${referer}'.`,
      };
    }
  }

  // 5. If neither Origin nor Referer is present on a state-changing request:
  // Reject if ambient session cookies are attached to prevent blind CSRF
  if (!origin && !referer) {
    const cookie = request.headers.get("cookie");
    if (cookie && cookie.includes("phishlens_refresh_token")) {
      return {
        valid: false,
        reason: "Cookie-authenticated state-changing requests require an Origin or Referer header.",
      };
    }
  }

  return { valid: true };
}

/**
 * Core proxy dispatcher.
 */
export async function handleProxyRequest(
  request: Request,
  pathSegments: string[]
): Promise<Response> {
  const method = request.method.toUpperCase();

  // Validate allowed methods
  if (!ALLOWED_METHODS.has(method)) {
    return Response.json(
      {
        error: {
          code: "METHOD_NOT_ALLOWED",
          message: `Method ${method} is not supported on this endpoint.`,
          status_code: 405,
          details: { allowed: Array.from(ALLOWED_METHODS) },
        },
      },
      {
        status: 405,
        headers: {
          Allow: Array.from(ALLOWED_METHODS).join(", "),
        },
      }
    );
  }

  if (method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        Allow: "GET, POST, OPTIONS",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers":
          "Content-Type, Authorization, X-Request-ID, Accept",
      },
    });
  }

  // Enforce deliberate CSRF defense on state-changing requests
  const csrfCheck = validateCsrfProtection(request);
  if (!csrfCheck.valid) {
    return Response.json(
      {
        error: {
          code: "CROSS_SITE_REQUEST_FORBIDDEN",
          message: "Cross-site request blocked: origin validation failed.",
          status_code: 403,
          details: { reason: csrfCheck.reason },
        },
      },
      { status: 403 }
    );
  }

  // Resolve backend target URL from server-only environment variable
  const backendBaseUrl =
    process.env.BACKEND_INTERNAL_URL || "http://localhost:8000";

  const reqUrl = new URL(request.url);
  const target = resolveTargetUrl(
    backendBaseUrl,
    pathSegments,
    reqUrl.search
  );

  if (!target.url || target.error) {
    return Response.json(
      {
        error: {
          code: "INVALID_PROXY_REQUEST",
          message: target.error || "Invalid request path.",
          status_code: 400,
          details: {},
        },
      },
      { status: 400 }
    );
  }

  // Build sanitized headers for upstream request
  const upstreamHeaders = new Headers();
  for (const [key, value] of request.headers.entries()) {
    const lowerKey = key.toLowerCase();
    if (!HOP_BY_HOP_HEADERS.has(lowerKey)) {
      upstreamHeaders.set(key, value);
    }
  }

  // Explicitly set Host for upstream
  try {
    const parsedTarget = new URL(target.url);
    upstreamHeaders.set("host", parsedTarget.host);
  } catch {
    // If URL parsing fails, let fetch use default
  }

  // Handle request body
  let bodyBuffer: ArrayBuffer | undefined = undefined;
  if (method === "POST") {
    try {
      bodyBuffer = await request.arrayBuffer();
    } catch {
      bodyBuffer = undefined;
    }
  }

  // Forward request with a 30s timeout
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 30000);

  try {
    const backendRes = await fetch(target.url, {
      method,
      headers: upstreamHeaders,
      body: bodyBuffer && bodyBuffer.byteLength > 0 ? bodyBuffer : undefined,
      redirect: "manual",
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    // Build response headers to return to browser
    const responseHeaders = new Headers();
    for (const [key, value] of backendRes.headers.entries()) {
      const lower = key.toLowerCase();
      if (lower !== "set-cookie" && !HOP_BY_HOP_HEADERS.has(lower)) {
        responseHeaders.set(key, value);
      }
    }

    // Safely extract Set-Cookie headers without merging
    let rawSetCookies: string[] = [];
    const headersAny = backendRes.headers as unknown as {
      getSetCookie?: () => string[];
    };
    if (typeof headersAny.getSetCookie === "function") {
      rawSetCookies = headersAny.getSetCookie();
    } else {
      const single = backendRes.headers.get("set-cookie");
      if (single) {
        rawSetCookies = [single];
      }
    }

    for (const cookie of rawSetCookies) {
      const transformed = transformSetCookie(cookie);
      if (transformed) {
        responseHeaders.append("set-cookie", transformed);
      }
    }

    const responseBody = await backendRes.arrayBuffer();
    return new Response(responseBody, {
      status: backendRes.status,
      statusText: backendRes.statusText,
      headers: responseHeaders,
    });
  } catch (err: unknown) {
    clearTimeout(timeoutId);
    if (err instanceof DOMException && err.name === "AbortError") {
      return Response.json(
        {
          error: {
            code: "UPSTREAM_TIMEOUT",
            message:
              "The upstream PhishLens AI backend service timed out while processing the request.",
            status_code: 504,
            details: {},
          },
        },
        { status: 504 }
      );
    }

    return Response.json(
      {
        error: {
          code: "BACKEND_UNAVAILABLE",
          message:
            "The upstream PhishLens AI backend service is currently unreachable.",
          status_code: 503,
          details: {},
        },
      },
      { status: 503 }
    );
  }
}
