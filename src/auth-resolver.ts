import { readCookie } from "./auth-cookie";
import type { AuthOptions, AuthResolver } from "./auth-types";
import type { AuthContext, AuthSession, Principal } from "./model";
import { JwtValidationError } from "./jwt-error";

const anonymous = <P extends Principal, S extends AuthSession>(): AuthContext<P, S> => ({
  authenticated: false,
  principal: null,
  session: null,
  tenant: null,
});
const usable = (session: AuthSession, now: number) =>
  session.revokedAt === undefined && (session.expiresAt === undefined || session.expiresAt > now);

export function createAuth<P extends Principal = Principal, S extends AuthSession = AuthSession>(
  options: AuthOptions<P, S> = {},
): AuthResolver<P, S> {
  const cookie = options.sessionCookie ?? "session";
  const clock = options.clock ?? Date.now;
  return {
    async resolve(request, resolveOptions = {}) {
      const signal = resolveOptions.signal ?? request.signal;
      const context = anonymous<P, S>();
      if (options.tenant)
        context.tenant =
          typeof options.tenant === "string"
            ? options.tenant
            : await options.tenant(request, { signal });
      const authorization = request.headers.get("authorization");
      if (options.jwt && /^Bearer\s/iu.test(authorization ?? "")) {
        const token = authorization!.replace(/^Bearer\s+/iu, "").trim();
        if (!token) return context;
        const validated = await options.jwt.validate(token);
        const principal = options.principals
          ? await options.principals.get(validated.subject ?? validated.id, { request, signal })
          : validated;
        if (!principal) return context;
        const claim = principal.scope;
        const scopes =
          typeof claim === "string"
            ? claim.split(/\s+/).filter(Boolean)
            : Array.isArray(claim)
              ? claim.filter((value): value is string => typeof value === "string")
              : undefined;
        return {
          authenticated: true,
          principal,
          session: null,
          tenant: context.tenant,
          ...(scopes ? { scopes } : {}),
        };
      }
      const jwtCookie =
        options.jwtCookie && readCookie(request.headers.get("cookie"), options.jwtCookie.name);
      if (options.jwtCookie && jwtCookie) {
        try {
          const validated = await options.jwtCookie.validator.validate(jwtCookie);
          const principal = options.principals
            ? await options.principals.get(validated.subject ?? validated.id, { request, signal })
            : validated;
          if (!principal) return context;
          return { authenticated: true, principal, session: null, tenant: context.tenant };
        } catch (error) {
          if (!(error instanceof JwtValidationError)) throw error;
        }
      }
      if (!options.sessions) return context;
      const id = readCookie(request.headers.get("cookie"), cookie);
      if (!id) return context;
      const session = await options.sessions.get(id, { request, signal });
      if (!session || !usable(session, clock())) return context;
      const principal = options.principals
        ? await options.principals.get(session.subject, { request, signal })
        : ({ id: session.subject, subject: session.subject } as P);
      return principal
        ? { authenticated: true, principal, session, tenant: context.tenant }
        : context;
    },
  };
}
