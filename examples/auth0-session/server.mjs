import { createServer } from "node:https";
import { generateKeyPairSync, randomBytes, createHash, sign } from "node:crypto";
import { readFile } from "node:fs/promises";

// Local demonstration only: interactive authorization signs in a fixed demo user.
const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...keys.publicKey.export({ format: "jwk" }), kid: "demo", alg: "RS256" };
const codes = new Map();
const providerSessions = new Map();
const expiresIn = Number(process.env.ASKR_AUTH_DEMO_TOKEN_SECONDS ?? 180);
let origin;
const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
const send = (response, status, value, headers = {}) => {
  response.writeHead(status, { "content-type": "application/json", ...headers });
  response.end(JSON.stringify(value));
};

const server = createServer(
  {
    key: await readFile(new URL("./localhost-key.pem", import.meta.url)),
    cert: await readFile(new URL("./localhost-cert.pem", import.meta.url)),
  },
  async (request, response) => {
    try {
      const url = new URL(request.url, origin);
      if (url.pathname === "/" || url.pathname === "/callback") {
        response.writeHead(200, { "content-type": "text/html" });
        response.end(await readFile(new URL("./index.html", import.meta.url)));
      } else if (/^\/auth\/[\w-]+\.js$/.test(url.pathname)) {
        response.writeHead(200, { "content-type": "text/javascript" });
        response.end(
          await readFile(
            new URL(`./node_modules/@askrjs/auth/dist/${url.pathname.slice(6)}`, import.meta.url),
          ),
        );
      } else if (url.pathname === "/sdk.js") {
        response.writeHead(200, { "content-type": "text/javascript" });
        response.end(
          await readFile(
            new URL(
              "./node_modules/@auth0/auth0-spa-js/dist/auth0-spa-js.production.esm.js",
              import.meta.url,
            ),
          ),
        );
      } else if (url.pathname === "/.well-known/openid-configuration") {
        send(response, 200, {
          issuer: `${origin}/`,
          authorization_endpoint: `${origin}/authorize`,
          token_endpoint: `${origin}/oauth/token`,
          jwks_uri: `${origin}/jwks`,
        });
      } else if (url.pathname === "/jwks") {
        send(response, 200, { keys: [jwk] });
      } else if (url.pathname === "/web-message") {
        response.writeHead(200, { "content-type": "text/html" });
        response.end('<script src="/web-message.js"></script>');
      } else if (url.pathname === "/web-message.js") {
        response.writeHead(200, { "content-type": "text/javascript" });
        response.end(`const params = new URL(location.href).searchParams;
        const response = { state: params.get('state') };
        if (params.has('error')) response.error = params.get('error');
        else response.code = params.get('code');
        parent.postMessage({ type: "authorization_response", response }, location.origin);`);
      } else if (url.pathname === "/authorize") {
        const params = url.searchParams;
        const redirect = new URL(params.get("redirect_uri"));
        if (
          redirect.href !== `${origin}/callback` ||
          params.get("client_id") !== "demo-spa" ||
          params.get("response_type") !== "code" ||
          params.get("code_challenge_method") !== "S256" ||
          !/^[\w-]{43}$/.test(params.get("code_challenge") ?? "") ||
          !params.get("nonce") ||
          !params.get("state")
        ) {
          send(response, 400, { error: "invalid_request" });
          return;
        }
        const cookie = /(?:^|;\s*)demo_oidc=([\w-]+)/.exec(request.headers.cookie ?? "")?.[1];
        const authenticated = (providerSessions.get(cookie) ?? 0) > Date.now();
        let result;
        if (params.get("prompt") === "none" && !authenticated)
          result = { state: params.get("state"), error: "login_required" };
        else {
          if (!authenticated) {
            const session = randomBytes(24).toString("base64url");
            providerSessions.set(session, Date.now() + 3_600_000);
            response.setHeader(
              "set-cookie",
              `demo_oidc=${session}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600`,
            );
          }
          for (const [key, transaction] of codes)
            if (transaction.expiresAt <= Date.now()) codes.delete(key);
          if (codes.size >= 100) {
            send(response, 429, { error: "too_many_requests" });
            return;
          }
          const code = randomBytes(24).toString("base64url");
          codes.set(code, {
            nonce: params.get("nonce"),
            challenge: params.get("code_challenge"),
            expiresAt: Date.now() + 60_000,
          });
          result = { state: params.get("state"), code };
        }
        if (params.get("response_mode") === "web_message") {
          const delivery = new URL("/web-message", origin);
          for (const [key, value] of Object.entries(result)) delivery.searchParams.set(key, value);
          response.writeHead(302, { location: delivery.href });
          response.end();
        } else {
          for (const [key, value] of Object.entries(result)) redirect.searchParams.set(key, value);
          response.writeHead(302, { location: redirect.href });
          response.end();
        }
      } else if (url.pathname === "/oauth/token" && request.method === "POST") {
        let body = "";
        for await (const chunk of request) {
          body += chunk;
          if (body.length > 8192) {
            send(response, 413, { error: "invalid_request" });
            return;
          }
        }
        const form = new URLSearchParams(body);
        const transaction = codes.get(form.get("code"));
        codes.delete(form.get("code"));
        const challenge = createHash("sha256")
          .update(form.get("code_verifier") ?? "")
          .digest("base64url");
        if (
          !transaction ||
          transaction.expiresAt <= Date.now() ||
          transaction.challenge !== challenge ||
          form.get("grant_type") !== "authorization_code" ||
          form.get("client_id") !== "demo-spa" ||
          form.get("redirect_uri") !== `${origin}/callback`
        ) {
          send(response, 400, { error: "invalid_grant" });
          return;
        }
        const data = `${encode({ alg: "RS256", kid: "demo" })}.${encode({ iss: `${origin}/`, aud: "demo-spa", sub: "demo-user", name: "Demo user", nonce: transaction.nonce, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600 })}`;
        send(response, 200, {
          token_type: "Bearer",
          access_token: randomBytes(24).toString("base64url"),
          expires_in: expiresIn,
          id_token: `${data}.${sign("RSA-SHA256", Buffer.from(data), keys.privateKey).toString("base64url")}`,
        });
      } else if (url.pathname === "/v2/logout" && request.method === "POST") {
        const cookie = /(?:^|;\s*)demo_oidc=([\w-]+)/.exec(request.headers.cookie ?? "")?.[1];
        providerSessions.delete(cookie);
        send(
          response,
          200,
          {},
          { "set-cookie": "demo_oidc=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0" },
        );
      } else send(response, 404, { error: "not_found" });
    } catch {
      send(response, 500, { error: "demo_server_error" });
    }
  },
);
server.listen(Number(process.env.ASKR_AUTH_DEMO_PORT ?? 8000), "127.0.0.1", () => {
  origin = `https://127.0.0.1:${server.address().port}`;
  process.stdout.write(`Demo ready at ${origin}\n`);
});
