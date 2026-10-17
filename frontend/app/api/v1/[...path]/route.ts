import { handleProxyRequest } from "@/lib/proxy";

interface RouteContext {
  params: Promise<{ path: string[] }>;
}

export async function GET(request: Request, context: RouteContext) {
  const { path } = await context.params;
  return handleProxyRequest(request, path);
}

export async function POST(request: Request, context: RouteContext) {
  const { path } = await context.params;
  return handleProxyRequest(request, path);
}

export async function OPTIONS(request: Request, context: RouteContext) {
  const { path } = await context.params;
  return handleProxyRequest(request, path);
}

export async function PUT(request: Request, context: RouteContext) {
  const { path } = await context.params;
  return handleProxyRequest(request, path);
}

export async function DELETE(request: Request, context: RouteContext) {
  const { path } = await context.params;
  return handleProxyRequest(request, path);
}

export async function PATCH(request: Request, context: RouteContext) {
  const { path } = await context.params;
  return handleProxyRequest(request, path);
}
