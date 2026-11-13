# Project Status and Remaining Work

**Project:** Password Storage Migration Design  
**Group:** 13  
**Purpose:** Track the implementation completed so far, the current demonstration capabilities, and work that remains before final submission.

> This status document reflects the implementation and testing information currently recorded by the project team. Items marked "implemented / exercised" have been described as working in the current local application. Items not verified in the available project notes are marked accordingly rather than assumed complete.

## 1. Project objective

Migrate a legacy authentication database that stores unsalted MD5 password hashes to Argon2id using rehash-on-next-login. Demonstrate the security improvement through controlled authentication tests, database inspection, and offline dictionary-cracking comparisons.

## 2. Dataset and environment

| Item | Current design |
|---|---|
| Group | 13 |
| Personalization seed | 13 mod 4 = 1 |
| Synthetic accounts | 1,000 |
| Common passwords | 500 (50%) |
| Weak variations | 300 (30%) |
| Strong random passwords | 200 (20%) |
| Database | SQLite |
| Web application | Flask |
| Password hashing | Legacy unsalted MD5; target Argon2id |
| Argon2id parameters | m=19 MiB (19,456 KiB), t=2, p=1 |
| Local development address | 127.0.0.1:5000 |

The dataset is synthetic. The ground-truth file is for evaluation only and must not be supplied to the cracking tool.

## 3. Implemented application functionality

### Authentication and migration

- [x] Flask login application backed by SQLite.
- [x] Legacy MD5 password verification.
- [x] Successful legacy login triggers Argon2id rehashing.
- [x] Legacy hash is replaced by the Argon2id hash on successful migration.
- [x] Subsequent login verifies using Argon2id.
- [x] User dashboard and administrator dashboard.
- [x] Migration progress and account/migration information are available in the administrator interface.

### Authentication protections and event logging

- [x] Failed-login event logging.
- [x] Successful-login event logging.
- [x] Account-based failure throttling.
- [x] Source-IP-based failure throttling.
- [x] Progressive delay behavior.
- [x] CSRF validation and rejection.
- [x] Argon2 verification concurrency-capacity protection.
- [x] Security event records distinguish manual request activity and automated demonstration activity in the current dashboard implementation.
- [x] Separate terminal monitor (`watch_demo.py`) for newly recorded security events.
- [x] Eastern Time display support; Windows setup requires the `tzdata` package if system time-zone data is unavailable.

Current protection values recorded in the implementation notes:

| Protection | Configured value |
|---|---:|
| Account failure threshold | 8 failures |
| Account failure window | 600 seconds |
| Source-IP failure threshold | 20 failures |
| Source-IP failure window | 300 seconds |
| Progressive cooldown sequence | 0, 0, 2, 4, 8, 16, 30 seconds |
| Concurrent Argon2 operations | 2 |

These are the current recorded values; verify the active `app.py` before presenting them as final configuration.

## 4. Tests already exercised

The following behaviors have been manually exercised in the local application according to the project notes:

- [x] Correct legacy credentials authenticate and trigger migration.
- [x] A subsequent login uses the migrated Argon2id hash.
- [x] Incorrect credentials are rejected without changing the stored password hash.
- [x] Progressive delays occur after repeated failed attempts.
- [x] Account failure threshold is enforced.
- [x] IP failure threshold is enforced across different account names from the same local source IP.
- [x] Missing/invalid CSRF token is rejected with HTTP 400.
- [x] Argon2 concurrency semaphore allows two occupied slots and rejects a third acquisition in the isolated capacity check.
- [x] Automated security demonstration suite previously reported all five checks passing: progressive delay, account throttling, IP throttling, CSRF rejection, and Argon2 capacity protection.
- [x] Live terminal monitor was exercised and displayed newly recorded events.

**Testing qualification:** The isolated semaphore check does not by itself prove that simultaneous real HTTP requests were tested under load. The automated rate-limit demonstration routines may use synthetic test history; label those as automated tests rather than real browser attempts.

## 5. Current dashboard and monitoring state

- The administrator dashboard has separate Manual tests and Automated tests tabs.
- The event list has source/category labels to distinguish manual browser/DevTools events from automated demonstration events.
- The event query limit was removed during the latest troubleshooting so the current event count/display logic could be inspected without the earlier row cap.
- The Clear event-history button has **not** been implemented. A previous attempt caused errors/side effects, so it was deferred.
- The live terminal monitor is working and should not be replaced unless a specific issue is found.
- The Windows timezone error was resolved by installing `tzdata` in the project's virtual environment.

The event-history counters should be checked to ensure they represent the intended metric (event totals versus complete test-run totals). Do not describe them as test-run counts unless the implementation explicitly counts runs.

## 6. Remaining implementation and validation work

### High priority

- [ ] Review the current `app.py` after the recent dashboard edits and confirm there are no unintended changes.
- [ ] Re-test both dashboard tabs after a clean Flask restart.
- [ ] Confirm manual browser/DevTools events appear only in the Manual tab.
- [ ] Confirm automated test events appear only in the Automated tab.
- [ ] Confirm displayed counters update consistently with newly recorded events.
- [ ] Implement a safe, clearly scoped event-history clearing feature only after backing up the database and verifying exactly which event tables/rows it affects. It must not reset accounts, password hashes, migration state, or rate-limit state.
- [ ] Verify the application from a clean GitHub clone using `requirements.txt`.
- [ ] Run the available pytest suite and record the results.

### Research demonstrations and analysis

- [ ] Complete or verify the offline dictionary attack against the MD5 sample.
- [ ] Complete or verify the equivalent Argon2id attack using the same candidate list and a documented, comparable attack budget.
- [ ] Record recovered-password counts, recovery rates, elapsed time, and exact Hashcat commands/configuration.
- [ ] Preserve the hash extracts and experiment outputs needed to reproduce the comparison.
- [ ] Keep the ground-truth file separate from all cracking inputs.
- [ ] Demonstrate and document database compromise scenarios before, during, and after migration.
- [ ] Finalize the inactive-account strategy, including the migration deadline and forced-reset behavior for accounts that remain unmigrated.
- [ ] Verify whether the proposed inactive-account handling is implemented or remains a design decision. Do not claim it is implemented until tested.

### Final project preparation

- [ ] Capture clear screenshots of migration before/after states.
- [ ] Capture manual authentication and security-protection evidence.
- [ ] Capture the automated test results with clear labels.
- [ ] Prepare a concise explanation of why Argon2id is more resistant to offline guessing than unsalted MD5.
- [ ] Document limitations: synthetic dataset, local development server, test-only credentials, and any unimplemented policies.
- [ ] Rehearse the live demonstration and ensure the demo accounts are not already rate-limited.
- [ ] Review the repository for secrets, real credentials, and ground-truth leakage before publishing to GitHub.

## 7. Important design decisions and limitations

- MD5 exists only to represent the legacy system; it is not suitable for new password storage.
- Rehash-on-next-login avoids an immediate password-reset requirement for active users.
- Inactive accounts require a clearly defined migration-deadline policy. The policy discussed by the team includes disabling accounts that remain unmigrated at the deadline and requiring password reset.
- Rate limiting should use temporary restrictions/progressive delays rather than permanent lockouts that could be abused for denial of service.
- Argon2 verification consumes resources; concurrent verification should remain bounded.
- This is an educational prototype, not a production-ready authentication service.

## 8. Next recommended work order

1. Freeze the currently working login and migration behavior.
2. Back up the current project and SQLite database.
3. Verify the manual/automated event separation and counters.
4. Implement event-history clearing as a separate, carefully tested change.
5. Complete and document the MD5-versus-Argon2id cracking experiment.
6. Finish inactive-account policy validation.
7. Run clean-environment tests and prepare presentation evidence.
