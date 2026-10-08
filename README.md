# Google Tasks MCP (read-only)

A single-user, read-only Google Tasks connector exposing MCP tools:
- list_tasklists
- list_tasks
- search_tasks
- get_task

## Google Cloud
Enable Google Tasks API. Create OAuth client type **Web application**. Use scope:
`https://www.googleapis.com/auth/tasks.readonly`

After deployment, set the authorised redirect URI to:
`https://YOUR_HOST/oauth/google/callback`

## Environment
Set:
- APP_BASE_URL
- GOOGLE_CLIENT_ID
- GOOGLE_CLIENT_SECRET
- GOOGLE_REFRESH_TOKEN (obtained from `/oauth/google/start` after first authorisation)
- MCP_AUTH_TOKEN (recommended)

## First-time OAuth
1. Deploy with APP_BASE_URL, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET.
2. Open `/oauth/google/start`.
3. Approve Google Tasks read-only access.
4. Copy the refresh token shown once and save it as GOOGLE_REFRESH_TOKEN in your hosting secrets.
5. Restart/redeploy.

## MCP
Endpoint: `https://YOUR_HOST/mcp`
If MCP_AUTH_TOKEN is set, send `Authorization: Bearer <token>`.
