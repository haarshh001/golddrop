# Gold Drop reward capture

For the configured one-number flow (registration, manual OTP, reward result), run:

```powershell
npm run check:dry
npm run check
```

The runner reads the phone and real photo path from `gold-settings.json`, and the remaining form fields from the saved prefetch capture. It opens a browser and pauses at OTP verification. Enter the OTP in the terminal, or enter it in the browser and click Verify OTP. It prints only the win type, reward object, and capture location after completion. `gold-settings.json` and `runs/` are ignored by Git because they contain personal data.

Run in PowerShell from this folder:

```powershell
npm install
npm run capture
```

The script opens a fresh visible browser at `https://golddropgolddhamaka.com/`. Complete the campaign normally in that browser, including the OTP you receive. Press Enter in the terminal or close the browser when finished. Do not reuse a previously submitted code merely to fill the recording; the result must come from a real run.

Each run creates `runs/<timestamp>/`:

| File | Content |
| --- | --- |
| `network.har` | Full request and response timeline with embedded bodies |
| `events.jsonl` | Ordered request, response, click, state, error and reward events |
| `bodies/` | Raw request and response bodies; decoded `resp` envelopes as JSON |
| `sources/` | Fetched HTML, JavaScript, CSS, images and other GET bodies |
| `states/` | HTML, visible text and full-page screenshots at route and response changes |
| `video/` | Browser recording, including transitions and animations |

If a run is interrupted before Playwright writes `network.har`, recover an index from the saved request and response bodies:

```powershell
python finalize_capture.py "runs/<timestamp>"
```

This creates `network.recovered.har`. It retains recorded headers and body bytes; request timing and HTTP version cannot be recovered.

The recorder only observes the browser session. It does not submit forms, enter OTPs, alter server responses, or claim rewards automatically. The output contains phone numbers, OTPs, access tokens, cookies and uploaded photos if you use them. Keep the run folder private; share a redacted copy if needed.

The configured `npm run check` mode does submit the registration and, if the OTP is entered in the terminal, verifies it. It does not repeat the Opella quiz or spin endpoints, which are absent from the observed Gold Drop flow.

To check the capture plumbing without entering personal details:

```powershell
npm run smoke
```

This loads the home page and clicks Get Started. A smoke run cannot verify the reward screen.

See [FINDINGS.md](FINDINGS.md) for the observed flow and remaining gaps.

## Raw API checker

`gold_api_checker.py` is the browser-free checker. It scans the Firebase databases in `link.txt`, confirms a number with a Zomato OTP, then runs the Gold Drop API flow (create → get-start → register → verify-otp). There is no browser, no quiz and no spin.

`link.txt` and `settings.json` are deliberately gitignored. On Railway they are created in the mounted volume through the dashboard; they are not part of the repository.

```powershell
pip install -r requirements.txt
python gold_api_checker.py --dry-run
python gold_api_checker.py
```

The dashboard listens on `http://localhost:5003`. Locally, use **Auto Divide** with your preferred instance count, then **Start All**, or just start the process: when `link.txt` exists, instances are created and started automatically. The proxy from `RAILWAY_PROXY` / `PROXY_URL` (or `settings.json` when no env var is set) is applied to Zomato and the Gold Drop API; Firebase scanning and Telegram use the direct connection, as in the Opella checker.

Rules implemented:

- A device is skipped when it has 5 BigCity messages dated today (IST), or when it is already marked as used for today. Both are evaluated at device visit, so at midnight the date changes and the device becomes eligible again.
- When a number returns `Please try again tomorrow using the same number` / `messageId: participation`, that number is cached in memory and the device is marked with today's date in `device_day_marks.json` in the volume. Attempts for that number stop, but the remaining numbers on the device are still processed in the current run. On restart, a device marked for today is skipped; tomorrow it is usable again.
- Each number gets up to `ATTEMPTS_PER_NUMBER` attempts (default 5) with a fresh session, a fresh Turnstile token and a fresh OTP. A token is solved only after Zomato/Instamart confirms the number, immediately before `register`.
- A proxy/transport failure before the token stage is retried in place with a 2/4/8s backoff and does not consume an attempt. A network failure after the token stage counts as a normal attempt, so no second solver token is bought for the same attempt.
- Zomato OTP is requested once per number before the attempts, as the liveness gate. If Zomato rejects the number or returns an error, the checker falls back to Instamart (`signin-check` then `send-otp`) and confirms the Instamart OTP arrives on the device. If Zomato accepts the send but its OTP never arrives, the number is skipped — no fallback in that case.
- Generated pincodes rotate through 100 real Telangana pincodes in `500001–509412`. A pincode the server rejects with `messageId: pincode` is written to `rejected_pincodes.json` in the volume and skipped in every future run, so no solver credit is spent on it again. Use **Reset rejected pincodes** on the Settings page to clear the list. If every pincode is rejected, the full pool is reused.
- Register uses the 285-byte 1×1 JPEG; the image bytes are outside the signed payload.
- On `win_type != "none"`, the entire decoded response is saved to `gold_hits.json` and sent to Telegram. A background watcher waits for the reward SMS, saves its code into the same hit record, sends it to Telegram, and then deletes that single message node from the Firebase inbox. If Telegram delivery fails, the SMS is left in the inbox.
- Proxy and network failures (`ProxyError`, tunnel timeout, connection pool exhaustion) are logged as errors but never sent to Telegram.

There are no `processed.txt` or `burned_phones.txt` files. Attempt counters are in memory and reset on restart.

## Railway deployment (24x7)

The repository does **not** contain `link.txt` or `settings.json`. Both are created inside the Railway volume after deployment, through the dashboard. Do not commit them.

### 1. Create the project

1. Push this folder to a private GitHub repository. Confirm `link.txt`, `settings.json`, `gold_hits.json` and `gold_instances.json` are **not** in the commit — `.gitignore` already excludes them.
2. In Railway, choose **New Project → Deploy from GitHub repo** and select that repository.
3. Railway detects Python from `requirements.txt` and uses the `Procfile` start command `python -u gold_api_checker.py`. There is intentionally no `runtime.txt` — pinning a Python version triggers a `mise` attestation failure on current Railway builders, so the service uses the platform default interpreter. The code has no version-specific dependencies beyond Python 3.

### 2. Add a persistent volume

1. In the project, open your service → **Settings → Volumes → Add Volume**.
2. Mount path: `/data`. Size: 1 GB is plenty.
3. In **Variables**, add:

| Variable | Value | Purpose |
| --- | --- | --- |
| `DATA_DIR` | `/data` | All runtime files live in the volume |
| `PORT` | leave to Railway | The app binds to whatever Railway injects |
| `NUM_INSTANCES` | `10` | Number of worker threads/shards |
| `AUTOSTART` | `1` | Create shards and start workers automatically |
| `RAILWAY_PROXY` | your proxy URL | Optional; otherwise set it in the dashboard Settings page |
| `TWOCAPTCHA_KEY` | your 2captcha key | Fallback Turnstile solver |
| `NOCAPTCHA_KEY` | your NoCaptchaAI key | Primary solver, 6,000 solves/day plan |
| `SOLVER_MODE` | `auto` | `auto`, `nocaptcha`, `sursolver` or `2captcha` |
| `SURSOLVER_KEYS` | `sur_...,sur_...` | Comma-separated SurSolver keys, one per account |
| `TOKEN_BUDGET` | `2000` | Hard stop on 2captcha solves |
| `ATTEMPTS_PER_NUMBER` | `3` | Attempts per number (campaign daily limit is 3) |
| `BIGCITY_DAILY_LIMIT` | `5` | Skip a device with this many BigCity SMS dated today |
| `NETWORK_RETRIES` | `3` | In-place retries for proxy/transport failures before the token stage |

`DATA_DIR` is the important one. Without the volume, `link.txt`, `settings.json`, `gold_instances.json`, `gold_hits.json` and `device_day_marks.json` are lost on every redeploy or restart.

### Solver chain

`SOLVER_MODE=auto` tries **NoCaptchaAI first** (task type `AntiTurnstileTask`, key in the JSON body). On any error it moves to the SurSolver key pool, which rotates round-robin with one concurrent task per key. SurSolver keys that report a quota/balance error are skipped for that UTC day. When no SurSolver key can solve, `auto` falls back to 2captcha. Explicit modes `nocaptcha`, `sursolver` and `2captcha` never fall through. SurSolver tokens are solved with its required Chrome 148 UA and the register request replays that same UA. Keys are never logged in full — only a masked prefix/suffix.

Every runtime setting is editable on the dashboard **Settings** page: proxy, solver keys and modes, budgets, device skip count, used-device marker toggle, attempts per number, liveness timeouts, reward watch duration, delete-SMS toggle and Telegram credentials. Each section has its own **Reset to default** button. Values are read live from `settings.json`, so changes apply without a restart.

### 3. Health check and scaling

- In **Settings → Health Check**, set the path to `/health` and the timeout to at least 30 seconds.
- Keep **Replicas = 1**. Do not use a multi-worker gunicorn command. Each process starts its own copy of the worker threads, so more than one process would scan the same numbers twice.

### 4. Deploy, then add the data through the dashboard

1. Deploy and wait until it is live.
2. Open the Railway-generated domain. The dashboard loads with zero links and no workers — a background watcher is waiting.
3. Go to **Firebase** → paste the full `link.txt` content (the Nexus export with `Label:` / `URL:` blocks) → Save.
4. Within 10 seconds the watcher creates `NUM_INSTANCES` shards, saves `gold_instances.json` in the volume and starts all workers. The dashboard shows them as Running.
5. If you did not set `RAILWAY_PROXY`, go to **Settings** → paste the proxy URL → Save. The next scan cycle picks it up without a restart.
6. Check `/health`. It reports `links`, `instances` and the list of running instance IDs.

### 5. What happens on restart/redeploy

On boot the app reads `gold_instances.json` from the volume and starts every configured instance automatically. Shards are not recreated if the file already exists, so your link edits survive. If you change the database list, use **Auto Divide** in the dashboard to rebuild the shards, then **Start All**.

### 6. Logs and verification

- Railway **Logs** shows the colored level tags: `[WIN]` green, `[ERROR]` red, `[NOREWARD]` amber, `[HIT]` cyan. ANSI colors do not render in Railway's log viewer, but the tags are there and the dashboard Logs page renders the colors.
- `/logs` in the dashboard shows the full in-memory buffer (up to 2,000 entries), newest first.
- A win writes `gold_hits.json` in the volume and sends the full decoded response to Telegram.

### 7. Common problems

| Symptom | Cause / fix |
| --- | --- |
| Health check fails | App must bind to `PORT`; this build already does. Confirm the health path is `/health`. |
| Dashboard shows zero instances | `link.txt` not added yet, or `DATA_DIR` points somewhere unexpected. Add links via the Firebase page. |
| Workers never start | `AUTOSTART=0`, or the watcher is still waiting for links. Check logs. |
| Zomato errors `Expecting value` | Proxy exit is blocked by Zomato. Replace `RAILWAY_PROXY` or the dashboard proxy. |
| Hits disappear after deploy | No volume mounted, or `DATA_DIR` not set to `/data`. |
| Duplicate registrations | More than one process/replica. Keep replicas at 1. |
| Build fails at `mise install` with "No GitHub artifact attestations found" | A `runtime.txt` is pinning a Python build without attestations. Do not add `runtime.txt`; if you must pin, set `MISE_PYTHON_GITHUB_ATTESTATIONS=false` in Railway variables. |

### Local test of the Railway configuration

```powershell
$env:DATA_DIR = "C:\railway-data-test"
$env:PORT = "5003"
$env:NUM_INSTANCES = "3"
python -u gold_api_checker.py
```

Create `link.txt` inside that data directory and the workers will auto-start.

