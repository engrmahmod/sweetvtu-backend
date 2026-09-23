# SWEETVTU Backend — real VTpass + Paystack

Flask API that powers the SWEETVTU site. Holds your VTpass and Paystack
**secret** keys safely on the server — they never appear in the website code.

## What it does
- Customer signup / login (passwords hashed, token sessions)
- Wallets stored in a real database (SQLite locally, Postgres if `DATABASE_URL` is set)
- Wallet funding via Paystack (initialize + verify, no webhook needed)
- Real purchases via VTpass: airtime, data, cable TV, electricity
- Failed VTpass purchases auto-refund the customer's wallet
- Admin endpoints (users, wallet adjust, transactions, prices, VTpass balance)

## Deploy (Render, free)
1. Create a free account at render.com and connect your GitHub.
2. New → Web Service → select this repo (`sweetvtu-backend` folder as root,
   or deploy the whole repo — `render.yaml` is included).
3. In the service's **Environment** tab, add these variables (get them from
   your VTpass profile → API Keys tab, and your Paystack dashboard → Settings → API Keys):
   - `VTPASS_API_KEY`, `VTPASS_PUBLIC_KEY`, `VTPASS_SECRET_KEY`
   - `VTPASS_SANDBOX` = `1` for testing, `0` for real money
   - `PAYSTACK_SECRET_KEY`, `PAYSTACK_PUBLIC_KEY`
   - `ADMIN_KEY` = any long random password you invent (protects admin endpoints)
   - `FRONTEND_ORIGIN` = `https://engrmahmod.github.io`
4. Deploy. Copy your service URL, e.g. `https://sweetvtu-backend.onrender.com`.
5. Put that URL into the website's `API_BASE` (top of the app script in `sweetvtu.html`)
   and re-upload `sweetvtu.html` to GitHub Pages.
6. Seed your data prices: call (with header `X-Admin-Key: <ADMIN_KEY>`)
   `POST https://<your-url>/api/admin/seed-prices` — matches your retail
   price list to VTpass plans. Then check
   `GET /api/admin/cost-check` for any plan priced below VTpass cost.

## Database note
Free Render disks are ephemeral: SQLite balances can reset on redeploys.
For real money, attach a free Postgres (Render / Neon / Supabase) and set
`DATABASE_URL` — the app switches to Postgres automatically.

## Test first
Keep `VTPASS_SANDBOX=1` and use VTpass sandbox test numbers (e.g. `08011111111`
simulates success) before switching to `0` for live.
