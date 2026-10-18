export async function GET() {
  const backendBaseUrl = (process.env.BACKEND_INTERNAL_URL || "http://localhost:8000").replace(/\/+$/, "");
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000);

  try {
    const res = await fetch(`${backendBaseUrl}/health`, {
      cache: "no-store",
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    const data = await res.json();
    return Response.json(data, {
      status: res.status,
      headers: {
        "Cache-Control": "no-store, max-age=0",
      },
    });
  } catch {
    clearTimeout(timeoutId);
    return Response.json(
      {
        status: "unreachable",
        app_name: "PhishLens AI API",
        environment: "proxy",
        timestamp: new Date().toISOString(),
        system: { python_version: "unknown", platform: "unknown" },
        models_loaded: {},
      },
      { status: 503 }
    );
  }
}
