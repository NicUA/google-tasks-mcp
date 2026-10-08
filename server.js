import express from "express";
import crypto from "crypto";
import { google } from "googleapis";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

const PORT = Number(process.env.PORT || 3000);
const BASE_URL = (process.env.APP_BASE_URL || "").replace(/\/$/, "");
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const GOOGLE_REFRESH_TOKEN = process.env.GOOGLE_REFRESH_TOKEN || "";
const MCP_AUTH_TOKEN = process.env.MCP_AUTH_TOKEN || "";

const ISSUER = BASE_URL || `http://localhost:${PORT}`;
const RESOURCE = ISSUER;
const GOOGLE_CALLBACK = `${ISSUER}/oauth/google/callback`;
const PRM = `${ISSUER}/.well-known/oauth-protected-resource`;

function oauthClient() {
  const client = new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_CALLBACK);
  if (GOOGLE_REFRESH_TOKEN) client.setCredentials({ refresh_token: GOOGLE_REFRESH_TOKEN });
  return client;
}

function tasksApi() {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GOOGLE_REFRESH_TOKEN) {
    throw new Error("Google OAuth is not configured.");
  }
  return google.tasks({ version: "v1", auth: oauthClient() });
}

function secretKey() {
  if (!MCP_AUTH_TOKEN || MCP_AUTH_TOKEN.length < 24) throw new Error("MCP_AUTH_TOKEN must be set to a long random value.");
  return MCP_AUTH_TOKEN;
}

function seal(obj) {
  const payload = Buffer.from(JSON.stringify(obj)).toString("base64url");
  const sig = crypto.createHmac("sha256", secretKey()).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}

function unseal(token, expectedType) {
  try {
    const [payload, sig] = String(token || "").split(".");
    if (!payload || !sig) return null;
    const expected = crypto.createHmac("sha256", secretKey()).update(payload).digest("base64url");
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const obj = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (expectedType && obj.typ !== expectedType) return null;
    if (obj.exp && Date.now() / 1000 > obj.exp) return null;
    return obj;
  } catch {
    return null;
  }
}

function getBearer(req) {
  const h = req.headers.authorization || "";
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1] : "";
}

function validAccess(req) {
  const t = unseal(getBearer(req), "access");
  if (!t) return null;
  if (t.aud !== RESOURCE || t.iss !== ISSUER) return null;
  if (!String(t.scope || "").split(/\s+/).includes("tasks:read")) return null;
  return t;
}

function challenge(res, desc = "OAuth authentication required") {
  res.set("WWW-Authenticate", `Bearer resource_metadata="${PRM}", scope="tasks:read", error="invalid_token", error_description="${desc}"`);
  return res.status(401).json({ error: "unauthorized" });
}

function cleanTask(t, listTitle) {
  return {
    id: t.id || null,
    tasklist: listTitle || null,
    title: t.title || "",
    notes: t.notes || "",
    status: t.status || null,
    due: t.due || null,
    completed: t.completed || null,
    updated: t.updated || null,
    parent: t.parent || null,
    position: t.position || null,
    hidden: Boolean(t.hidden),
    deleted: Boolean(t.deleted),
    webViewLink: t.webViewLink || null
  };
}

async function getLists() {
  const api = tasksApi();
  let pageToken;
  const lists = [];
  do {
    const r = await api.tasklists.list({ maxResults: 100, pageToken });
    for (const item of r.data.items || []) {
      lists.push({ id: item.id, title: item.title, updated: item.updated || null });
    }
    pageToken = r.data.nextPageToken || undefined;
  } while (pageToken);
  return lists;
}

async function getTasksForList(tasklistId, listTitle, opts = {}) {
  const api = tasksApi();
  let pageToken;
  const out = [];
  do {
    const r = await api.tasks.list({
      tasklist: tasklistId,
      maxResults: 100,
      pageToken,
      showCompleted: true,
      showHidden: true,
      showDeleted: false,
      ...opts
    });
    for (const t of r.data.items || []) out.push(cleanTask(t, listTitle));
    pageToken = r.data.nextPageToken || undefined;
  } while (pageToken);
  return out;
}

const server = new McpServer({ name: "google-tasks-readonly", version: "1.1.0" });

server.tool(
  "list_tasklists",
  "List all Google Tasks task lists. Read-only.",
  {},
  async () => ({ content: [{ type: "text", text: JSON.stringify(await getLists()) }] })
);

server.tool(
  "list_tasks",
  "List tasks in a Google Tasks list, including completed tasks. Read-only.",
  {
    tasklist_id: z.string(),
    updated_min: z.string().optional(),
    completed_min: z.string().optional()
  },
  async ({ tasklist_id, updated_min, completed_min }) => {
    const lists = await getLists();
    const list = lists.find(x => x.id === tasklist_id);
    const tasks = await getTasksForList(tasklist_id, list?.title, {
      updatedMin: updated_min || undefined,
      completedMin: completed_min || undefined
    });
    return { content: [{ type: "text", text: JSON.stringify(tasks) }] };
  }
);

server.tool(
  "search_tasks",
  "Search across all Google Tasks lists by title or notes, optionally filtered by date range and status. Read-only.",
  {
    query: z.string().default(""),
    from: z.string().optional(),
    to: z.string().optional(),
    status: z.enum(["all", "needsAction", "completed"]).default("all"),
    limit: z.number().int().min(1).max(1000).default(500)
  },
  async ({ query, from, to, status, limit }) => {
    const lists = await getLists();
    const q = query.trim().toLowerCase();
    const fromMs = from ? Date.parse(from) : null;
    const toMs = to ? Date.parse(to.length === 10 ? `${to}T23:59:59.999Z` : to) : null;
    const results = [];
    for (const list of lists) {
      const tasks = await getTasksForList(list.id, list.title);
      for (const task of tasks) {
        if (status !== "all" && task.status !== status) continue;
        const hay = `${task.title}\n${task.notes}`.toLowerCase();
        if (q && !hay.includes(q)) continue;
        if (fromMs !== null || toMs !== null) {
          const dates = [task.due, task.completed, task.updated].filter(Boolean).map(Date.parse).filter(Number.isFinite);
          if (!dates.length) continue;
          if (!dates.some(ms => (fromMs === null || ms >= fromMs) && (toMs === null || ms <= toMs))) continue;
        }
        results.push(task);
        if (results.length >= limit) break;
      }
      if (results.length >= limit) break;
    }
    return { content: [{ type: "text", text: JSON.stringify(results) }] };
  }
);

server.tool(
  "get_task",
  "Get one Google Task by task list ID and task ID. Read-only.",
  { tasklist_id: z.string(), task_id: z.string() },
  async ({ tasklist_id, task_id }) => {
    const api = tasksApi();
    const lists = await getLists();
    const list = lists.find(x => x.id === tasklist_id);
    const r = await api.tasks.get({ tasklist: tasklist_id, task: task_id });
    return { content: [{ type: "text", text: JSON.stringify(cleanTask(r.data, list?.title)) }] };
  }
);

app.get("/", (req, res) => {
  const ready = Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET && GOOGLE_REFRESH_TOKEN);
  res.type("html").send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Tasks Connector</title></head><body style="font-family:system-ui;max-width:760px;margin:40px"><h1>Tasks Connector</h1><p>${ready ? "Google Tasks connected" : "Google Tasks OAuth not finished"}</p><p>MCP: <code>${ISSUER}/mcp</code></p><p>OAuth metadata: <code>${ISSUER}/.well-known/oauth-authorization-server</code></p><p>Read-only.</p></body></html>`);
});

app.get("/health", (req, res) => res.json({
  ok: true,
  googleConfigured: Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET && GOOGLE_REFRESH_TOKEN),
  oauthConfigured: Boolean(MCP_AUTH_TOKEN),
  mcpUrl: `${ISSUER}/mcp`
}));

app.get("/.well-known/oauth-protected-resource", (req, res) => res.json({
  resource: RESOURCE,
  authorization_servers: [ISSUER],
  scopes_supported: ["tasks:read"],
  resource_documentation: `${ISSUER}/`
}));

app.get("/.well-known/oauth-authorization-server", (req, res) => res.json({
  issuer: ISSUER,
  authorization_response_iss_parameter_supported: true,
  authorization_endpoint: `${ISSUER}/oauth/authorize`,
  token_endpoint: `${ISSUER}/oauth/token`,
  registration_endpoint: `${ISSUER}/oauth/register`,
  token_endpoint_auth_methods_supported: ["none"],
  code_challenge_methods_supported: ["S256"],
  scopes_supported: ["tasks:read"],
  response_types_supported: ["code"],
  grant_types_supported: ["authorization_code", "refresh_token"]
}));

app.post("/oauth/register", (req, res) => {
  const redirects = Array.isArray(req.body.redirect_uris) ? req.body.redirect_uris : [];
  if (!redirects.length || !redirects.every(x => typeof x === "string" && x.startsWith("https://chatgpt.com/"))) {
    return res.status(400).json({ error: "invalid_redirect_uri" });
  }
  const client_id = seal({ typ: "client", redirect_uris: redirects, iat: Math.floor(Date.now()/1000) });
  res.status(201).json({
    client_id,
    client_id_issued_at: Math.floor(Date.now()/1000),
    redirect_uris: redirects,
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"]
  });
});

app.get("/oauth/authorize", (req, res) => {
  const client = unseal(req.query.client_id, "client");
  const redirect_uri = String(req.query.redirect_uri || "");
  const response_type = String(req.query.response_type || "");
  const code_challenge = String(req.query.code_challenge || "");
  const method = String(req.query.code_challenge_method || "");
  const resource = String(req.query.resource || "");
  const scope = String(req.query.scope || "tasks:read");
  const state = String(req.query.state || "");
  if (!client || !client.redirect_uris.includes(redirect_uri) || response_type !== "code" || method !== "S256" || !code_challenge) {
    return res.status(400).send("Invalid OAuth request");
  }
  if (resource !== RESOURCE || !scope.split(/\s+/).includes("tasks:read")) {
    return res.status(400).send("Invalid resource or scope");
  }
  const request = seal({
    typ: "authreq",
    client_id: String(req.query.client_id),
    redirect_uri,
    code_challenge,
    resource,
    scope,
    state,
    exp: Math.floor(Date.now()/1000) + 600
  });
  res.type("html").send(`<!doctype html><html><body style="font-family:system-ui;max-width:560px;margin:50px auto;padding:20px"><h2>Connect Google Tasks to ChatGPT</h2><p>This grants read-only access to your Google Tasks through your private connector.</p><form method="post" action="/oauth/approve"><input type="hidden" name="request" value="${request}"><label>Connector password<br><input type="password" name="password" required style="width:100%;padding:10px;margin:8px 0 16px"></label><button type="submit" style="padding:10px 18px">Allow</button></form></body></html>`);
});

app.post("/oauth/approve", (req, res) => {
  if (!MCP_AUTH_TOKEN || String(req.body.password || "") !== MCP_AUTH_TOKEN) {
    return res.status(403).send("Incorrect connector password");
  }
  const ar = unseal(req.body.request, "authreq");
  if (!ar) return res.status(400).send("Expired or invalid authorization request");
  const code = seal({
    typ: "code",
    client_id: ar.client_id,
    redirect_uri: ar.redirect_uri,
    code_challenge: ar.code_challenge,
    resource: ar.resource,
    scope: ar.scope,
    exp: Math.floor(Date.now()/1000) + 300
  });
  const u = new URL(ar.redirect_uri);
  u.searchParams.set("code", code);
  if (ar.state) u.searchParams.set("state", ar.state);
  u.searchParams.set("iss", ISSUER);
  res.redirect(u.toString());
});

app.post("/oauth/token", (req, res) => {
  const grant = String(req.body.grant_type || "");
  if (grant === "authorization_code") {
    const code = unseal(req.body.code, "code");
    if (!code) return res.status(400).json({ error: "invalid_grant" });
    if (String(req.body.client_id || "") !== code.client_id || String(req.body.redirect_uri || "") !== code.redirect_uri) {
      return res.status(400).json({ error: "invalid_grant" });
    }
    const verifier = String(req.body.code_verifier || "");
    const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
    if (challenge !== code.code_challenge) return res.status(400).json({ error: "invalid_grant" });
    if (String(req.body.resource || "") !== code.resource) return res.status(400).json({ error: "invalid_target" });
    const now = Math.floor(Date.now()/1000);
    const access_token = seal({ typ:"access", iss:ISSUER, aud:RESOURCE, scope:code.scope, sub:"owner", iat:now, exp:now+3600 });
    const refresh_token = seal({ typ:"refresh", iss:ISSUER, aud:RESOURCE, scope:code.scope, sub:"owner", client_id:code.client_id, iat:now, exp:now+2592000 });
    return res.json({ access_token, token_type:"Bearer", expires_in:3600, refresh_token, scope:code.scope });
  }
  if (grant === "refresh_token") {
    const rt = unseal(req.body.refresh_token, "refresh");
    if (!rt || String(req.body.client_id || "") !== rt.client_id) return res.status(400).json({ error:"invalid_grant" });
    if (String(req.body.resource || "") !== RESOURCE) return res.status(400).json({ error:"invalid_target" });
    const now = Math.floor(Date.now()/1000);
    const access_token = seal({ typ:"access", iss:ISSUER, aud:RESOURCE, scope:rt.scope, sub:"owner", iat:now, exp:now+3600 });
    return res.json({ access_token, token_type:"Bearer", expires_in:3600, scope:rt.scope });
  }
  return res.status(400).json({ error:"unsupported_grant_type" });
});

app.get("/oauth/google/start", (req, res) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) return res.status(500).send("Set Google OAuth credentials first.");
  const state = crypto.randomBytes(18).toString("hex");
  const url = oauthClient().generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: ["https://www.googleapis.com/auth/tasks.readonly"],
    state
  });
  res.redirect(url);
});

app.get("/oauth/google/callback", async (req, res) => {
  try {
    const code = String(req.query.code || "");
    if (!code) return res.status(400).send("Missing code");
    const { tokens } = await oauthClient().getToken(code);
    if (!tokens.refresh_token) return res.status(400).send("No refresh token returned.");
    res.type("html").send(`<!doctype html><html><body style="font-family:system-ui;max-width:760px;margin:40px"><h2>Google Tasks authorised</h2><p>Copy this value into Render as <b>GOOGLE_REFRESH_TOKEN</b>.</p><textarea style="width:100%;height:140px">${tokens.refresh_token}</textarea></body></html>`);
  } catch (e) {
    res.status(500).send(`OAuth error: ${String(e.message || e)}`);
  }
});

app.all("/mcp", async (req, res) => {
  if (!validAccess(req)) return challenge(res);
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => transport.close().catch(() => {}));
  await server.connect(transport);
  await transport.handleRequest(req, res, req.method === "POST" ? req.body : undefined);
});

app.listen(PORT, "0.0.0.0", () => console.log(`Tasks Connector listening on ${PORT}`));
