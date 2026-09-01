# CIVITAS Kashmir Backend

Render Free + Neon-ready backend for the CIVITAS website.

## Render + Neon

1. Create a Neon Postgres project.
2. Copy the Neon connection string from **Connect**.
3. In Render, open the service's **Environment** settings.
4. Add:

   `DATABASE_URL` = your full Neon Postgres connection string

5. Deploy the latest commit.

The server creates the `civitas_store` table automatically on first startup. Site content, applications, submissions, messages, activity logs and member accounts are stored in Neon when `DATABASE_URL` is configured.

If `DATABASE_URL` is missing, the app falls back to local JSON files. That fallback is useful for local development, but Render's free filesystem is ephemeral, so production persistence requires Neon.

## Health check

Open `/api/health` on the deployed site. A successful Neon connection returns JSON containing:

`{"ok":true,"database":"neon"}`

## Admin backup

Control Mode includes **Download Data Backup**. The backup can be restored through the server endpoint after authentication if needed.

## Department leadership

The Communications & Social Media department supports Head, Deputy Head, and Chief Editor, each with an optional circular DP photo. Photos are resized in the browser before being saved to the content record.


## Render control-mode environment variables

For a simple Render setup, you may use `ADMIN_CODE` and `DEPUTY_CODE` directly instead of bcrypt hashes. These are server-only environment variables and are never sent to the browser. Example:

`ADMIN_NAMES=Ayaan,Qazi Hazeem,Mir Muazzam`

`ADMIN_CODE=22062011`

`DEPUTY_NAME=Deputy`

`DEPUTY_CODE=2017CR7`

`DATABASE_URL=<your Neon connection string>`
