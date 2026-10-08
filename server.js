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

const callbackUrl = `${BASE_URL || "http://localhost:" + PORT}/oauth/google/callback`;

function oauthClient() {
  const client = new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, callbackUrl);
  if (GOOGLE_REFRESH_TOKEN) client.setCredentials({ refresh_token: GOOGLE_REFRESH_TOKEN });
  return client;
}

function tasksApi() {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GOOGLE_REFRESH_TOKEN) {
    throw new Error("Google OAuth is not configured. Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and GOOGLE_REFRESH_TOKEN.");
  }
  return google.tasks({ version: "v1", auth: oauthClient() });
}

function authOk(req) {
  if (!MCP_AUTH_TOKEN) return true;
  const hdr = req.headers.authorization || "";
  return hdr === `Bearer ${MCP_AUTH_TOKEN}`;
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
    for (const item of r.data.items || []) lists.push({ id: item.id, title: item.title, updated: item.updated || null });
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

const server = new McpServer({ name: "google-tasks-readonly", version: "1.0.0" });

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
    updated_min: z.string().optional().describe("RFC3339 lower bound for updated time"),
    completed_min: z.string().optional().describe("RFC3339 lower bound for completed time")
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
    from: z.string().optional().describe("YYYY-MM-DD or RFC3339; checks due/completed/updated"),
    to: z.string().optional().describe("YYYY-MM-DD or RFC3339; checks due/completed/updated"),
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
          const inRange = dates.some(ms => (fromMs === null || ms >= fromMs) && (toMs === null || ms <= toMs));
          if (!inRange) continue;
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
  res.type("html").send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Tasks Connector</title><style>body{font-family:system-ui;margin:40px;max-width:760px}code{background:#eee;padding:2px 6px;border-radius:6px}.ok{color:#087a38}.bad{color:#b42318}a{display:inline-block;margin:8px 0}</style></head><body><h1>Tasks Connector</h1><p class="${ready ? "ok" : "bad"}">${ready ? "Google Tasks connected" : "Google Tasks OAuth not finished"}</p><p>OAuth callback: <code>${callbackUrl}</code></p><p>MCP endpoint: <code>${BASE_URL ? BASE_URL + "/mcp" : "Set APP_BASE_URL after deploy"}</code></p><p>Health: <a href="/health">/health</a></p>${GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET && !GOOGLE_REFRESH_TOKEN ? '<p><a href="/oauth/google/start">Connect Google Tasks</a></p>' : ''}<p>Read-only: this service has no create/update/delete tools.</p></body></html>`);
});

app.get("/health", (req, res) => res.json({ ok: true, googleConfigured: Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET && GOOGLE_REFRESH_TOKEN), callbackUrl, mcpUrl: BASE_URL ? `${BASE_URL}/mcp` : null }));

app.get("/oauth/google/start", (req, res) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) return res.status(500).send("Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET first.");
  const state = crypto.randomBytes(18).toString("hex");
  const client = oauthClient();
  const url = client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: ["https://www.googleapis.com/auth/tasks.readonly"],
    state
  });
  res.cookie?.("oauth_state", state, { httpOnly: true, sameSite: "lax", secure: BASE_URL.startsWith("https://") });
  res.redirect(url);
});

app.get("/oauth/google/callback", async (req, res) => {
  try {
    const code = String(req.query.code || "");
    if (!code) return res.status(400).send("Missing code");
    const client = oauthClient();
    const { tokens } = await client.getToken(code);
    if (!tokens.refresh_token) {
      return res.status(400).type("html").send("<h2>No refresh token returned</h2><p>Remove this app from your Google Account permissions and try Connect again.</p>");
    }
    res.type("html").send(`<!doctype html><html><body style="font-family:system-ui;max-width:760px;margin:40px"><h2>Google Tasks authorised</h2><p>Copy this value into your hosting environment as <b>GOOGLE_REFRESH_TOKEN</b>, then restart the service.</p><textarea style="width:100%;height:140px">${tokens.refresh_token}</textarea><p>Keep it secret. It grants read-only access to your Google Tasks.</p></body></html>`);
  } catch (e) {
    res.status(500).send(`OAuth error: ${String(e.message || e)}`);
  }
});

app.post("/mcp", async (req, res) => {
  if (!authOk(req)) return res.status(401).json({ error: "unauthorized" });
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => transport.close().catch(() => {}));
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.get("/mcp", (req, res) => res.status(405).send("Use POST for MCP Streamable HTTP."));
app.delete("/mcp", (req, res) => res.status(405).send("No sessions are stored."));

app.listen(PORT, "0.0.0.0", () => console.log(`Tasks Connector listening on ${PORT}`));
