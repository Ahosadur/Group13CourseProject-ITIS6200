# Running the Password Migration Project

This guide explains how to set up the Group 13 Password Migration Project from a GitHub clone on Windows PowerShell. The commands can be adapted for macOS or Linux.

**Important:** The SQLite database and generated password dataset are intentionally not committed to GitHub. A new user must generate the synthetic dataset and database locally before starting Flask.

## 1. Prerequisites

Install:

- Python 3.10 or newer.
- Git.
- A terminal such as PowerShell.
- Hashcat only if running the offline-cracking experiments.

Check Python and Git:

```powershell
python --version
git --version
```

## 2. Clone the repository

```powershell
git clone <YOUR-GITHUB-REPOSITORY-URL>
cd Password-Migration-Project
```

Replace the placeholder URL with your actual GitHub repository URL.

## 3. Create and activate a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation for the current session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

You should see `(.venv)` at the beginning of the prompt.

## 4. Install dependencies

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

The project's dependencies include Flask, argon2-cffi, Flask-Limiter, pytest, and tzdata. `tzdata` supplies IANA timezone data for Python's `zoneinfo` on Windows systems where it is not otherwise available.

Verify the Eastern timezone:

```powershell
python -c "from zoneinfo import ZoneInfo; print(ZoneInfo('America/New_York'))"
```

Expected output:

```text
America/New_York
```

## 5. Generate the local synthetic dataset and SQLite database

Because `data/` is not included in the GitHub repository, each person cloning the project must generate their own local dataset and database.

First, locate the dataset-generation script committed in the repository. In the commands below, `generate_dataset.py` is the expected example filename. If the actual script has a different name, use that filename instead.

From the project root, with `.venv` activated, run:

```powershell
python generate_dataset.py
```

The generator should create the `data/` directory and the files required by the application, normally:

```text
data/
├── users.db
└── ground_truth.csv
```

**Important checks:**

- Confirm the generator uses the Group 13 personalization seed (`13 mod 4 = 1`) and creates 1,000 synthetic accounts with the intended 50% common, 30% weak-variation, and 20% strong-random distribution.
- Confirm the generated SQLite database is initialized with the schema expected by the current `app.py`.
- Keep `ground_truth.csv` local and separate from all cracking inputs. Never provide it to Hashcat.
- Run the generator only when creating a fresh dataset. Re-running it may overwrite or replace the existing database and reset account migration/test state. Back up any database you want to preserve first.

If your repository uses a different generator command or requires a separate database-initialization script, update this section to match the actual committed scripts before publishing the README. Do not assume the application can start successfully until the database has been generated.

## 6. Start the Flask application

After generating the database, start Flask from the project root:

```powershell
python app.py
```

The local development server should report an address similar to:

```text
http://127.0.0.1:5000
```

Open that address in a browser on the same computer.

The Flask development server is for local coursework demonstrations. Do not expose it directly to the public internet.

## 7. Start the live terminal monitor

Open a **second** PowerShell window. Change to the same project directory and activate the virtual environment:

```powershell
cd "PATH\TO\Password-Migration-Project"
.\.venv\Scripts\Activate.ps1
python watch_demo.py
```

Start the monitor before performing the actions you want it to display. It is designed to show newly recorded events after startup and may not replay earlier history.

Keep Flask running in the first terminal and the monitor running in the second terminal. Use `Ctrl+C` in each terminal to stop that process.

## 8. Suggested demonstration sequence

Use only the generated synthetic accounts.

1. Open the application and confirm the login page loads.
2. Submit an incorrect password and observe the failed-login event.
3. Log in with a valid legacy account and verify that it migrates to Argon2id.
4. Log out and log in again to demonstrate direct Argon2id verification.
5. Use a separate test account to demonstrate progressive delays and account throttling.
6. Use multiple synthetic accounts from the same local source IP to demonstrate IP throttling, subject to the configured limits.
7. Use browser Developer Tools to submit a request without a valid CSRF token and observe the rejection.
8. Run the administrator's automated security tests and inspect their results separately from manual browser activity.
9. If running the offline-cracking experiment, use the designated hash extracts and candidate list, and keep ground truth separate.

Avoid repeatedly testing against an account needed for a later demonstration: rate-limit state may persist in the database until its configured time window expires.

## 9. Run tests

If the repository includes pytest test files, run:

```powershell
pytest
```

Some tests may require a dedicated test database or environment variables. Follow the test-specific instructions in the repository. Do not run destructive tests against the only copy of your demonstration database.

## 10. GitHub publishing checklist

Before pushing the project:

- [ ] Do not commit `.venv/`.
- [ ] Do not commit `__pycache__/` or `.pytest_cache/`.
- [ ] Do not commit generated secret keys, real credentials, or `.env` files.
- [ ] Do not commit `data/users.db` if the intention is for each clone to generate its own database.
- [ ] Do not commit `data/ground_truth.csv`; keep it local and separate from cracking inputs.
- [ ] Do not include real user data or real passwords.
- [ ] Commit the dataset-generation script and any database-initialization scripts needed to recreate the local environment.
- [ ] Include `requirements.txt`, `README.md`, this guide, and `PROJECT_STATUS.md`.
- [ ] Verify the full setup from a clean clone on a machine that does not already have the database.

A typical `.gitignore` should include:

```gitignore
.venv/
__pycache__/
*.py[cod]
.pytest_cache/
.env
*.log
.DS_Store
data/
```

The `data/` rule keeps the generated database, ground truth, and other local dataset artifacts out of Git. If the project later needs to publish a safe, non-sensitive sample input file, explicitly allowlist that file rather than committing the full data directory.
