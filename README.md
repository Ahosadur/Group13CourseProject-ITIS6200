# Password Storage Migration Design

**Group 13 – Password Migration Project**

## Project Overview

This project demonstrates the migration of a legacy password-storage system that uses unsalted MD5 hashes to a more secure Argon2id password-hashing system.

The application uses a **rehash-on-next-login** approach. Existing users do not need to reset their passwords immediately: when a user successfully authenticates with the legacy password, the application hashes the submitted password with Argon2id and replaces the legacy MD5 hash.

The project also provides a controlled environment for demonstrating authentication protections and comparing the offline-cracking resistance of legacy MD5 hashes and Argon2id hashes.

## Technology Stack

- Python
- Flask
- SQLite
- MD5 (legacy demonstration only)
- Argon2id (`argon2-cffi`)
- Hashcat (offline cracking demonstrations)
- Flask-Limiter (dependency for rate-limiting functionality)
- pytest (testing)
- HTML, CSS, and JavaScript for the web interface

## Group Personalization and Synthetic Dataset

- **Group number:** 13
- **Personalization calculation:** 13 mod 4 = 1
- **Dataset size:** 1,000 synthetic user accounts
- **Password distribution:**
  - 500 common passwords (50%)
  - 300 weak password variations (30%)
  - 200 strong random passwords (20%)

Common passwords are sourced from SecLists. Weak variations are generated using common password patterns. Strong passwords are independently generated.

The dataset is synthetic and is intended for controlled academic experimentation. Do not use real user passwords or real account data.

## Migration Mechanism

1. A user submits their username and password.
2. For a legacy account, the application verifies the submitted password against its stored unsalted MD5 hash.
3. If authentication succeeds, the submitted plaintext password is immediately hashed using Argon2id.
4. The Argon2id hash replaces the legacy MD5 hash in the SQLite database.
5. On subsequent logins, the application verifies the password directly with Argon2id.
6. The migration state and migration activity are tracked by the application.

The intended end state is that migrated accounts no longer retain their original MD5 password hash.

## Security Demonstrations

The application and project plan cover the following demonstrations:

- Successful and unsuccessful login attempts.
- Rehash-on-next-login migration from MD5 to Argon2id.
- Verification of subsequent Argon2id logins.
- Progressive delays and temporary restrictions after repeated failures.
- Account-based and source-IP-based throttling.
- CSRF rejection.
- Argon2 verification-capacity protection.
- Inactive-account handling and migration-deadline policy.
- Offline dictionary attacks against MD5 and Argon2id hashes using Hashcat.
- Comparison of cracking outcomes under a consistent candidate list and attack budget.
- Database-compromise scenarios before, during, and after migration.

Some demonstrations and policy items may still be under development. See [PROJECT_STATUS.md](PROJECT_STATUS.md) for the current implementation status and remaining work.

## Application and Event Monitoring

The Flask application provides user and administrator interfaces. The administrator interface includes migration information and authentication security events.

Security events are separated into manual browser/DevTools activity and automated demonstration activity where supported by the current application version. `watch_demo.py` is a separate terminal monitor for newly recorded events. Start it in a second terminal after starting Flask.

Event-history clearing is not currently documented as an available feature. Do not manually delete database tables or event records unless you have backed up the database and understand the effect.

## Repository Contents

The exact repository layout may evolve. A typical local project contains:

```text
Password-Migration-Project/
├── app.py
├── watch_demo.py
├── requirements.txt
├── README.md
├── RUNNING_THE_PROJECT.md
├── PROJECT_STATUS.md
├── data/
│   ├── users.db
│   └── ground_truth.csv
└── ... supporting scripts, templates, and experiment files
```

Do not commit real credentials, secret keys, virtual environments, caches, or sensitive data. Review the data files before publishing the repository. In particular, `ground_truth.csv` contains synthetic password ground truth and should not be included in a public repository used for the cracking demonstration.

## Important Security and Academic Scope

This is an educational prototype, not a production authentication service. The Flask development server is intended for local demonstrations. Do not expose it directly to the public internet or use it to store real passwords.

MD5 is retained only to represent the legacy system and should not be used for new password storage.
