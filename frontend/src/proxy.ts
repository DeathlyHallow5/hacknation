import { NextResponse, type NextRequest } from "next/server";

/**
 * Route guard: pages need a session cookie. The real check happens in the API
 * (mock or Rust) which answers 401 when the session is invalid.
 */
const SESSION_COOKIE = process.env.ASI_SESSION_COOKIE ?? "asi_session";
const PUBLIC_PAGES = ["/login", "/dostepnosc"];

export function proxy(request: NextRequest) {
  const { pathname, search } = request.nextUrl;
  if (PUBLIC_PAGES.some((p) => pathname === p || pathname.startsWith(`${p}/`))) return NextResponse.next();
  if (!request.cookies.has(SESSION_COOKIE)) {
    const url = request.nextUrl.clone();
    url.pathname = "/login";
    url.search = pathname === "/" ? "" : `?next=${encodeURIComponent(pathname + search)}`;
    return NextResponse.redirect(url);
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico|icon.svg|brand|samples|.*\\.(?:svg|png|jpg|ico|webp|txt|csv|json|yaml)$).*)"],
};
