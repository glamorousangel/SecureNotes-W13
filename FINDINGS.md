# Vulnerability Findings — <Dorothy Miles> & <Jose Brian>

There are **6** security bugs planted in `app/main.py`. The findings below map each planted issue to the OWASP Top 10 (2025) risk required by the activity.

| # | OWASP 2025 code & name | Where (route / line) | How an attacker abuses it | Your fix (1 line) |
|---|------------------------|----------------------|---------------------------|-------------------|
| 1 | **A01 — Broken Access Control** | `GET /notes/{note_id}` | An authenticated user can request another user's note ID because the query checks only the note ID, not its owner. Alice can therefore read Bob's note. | Query the note using both `note_id` and the authenticated user's `owner_id`. |
| 2 | **A02 — Security Misconfiguration** | App configuration, `SECRET_KEY`, CORS middleware, and exception handler | The app exposes a hardcoded signing secret, allows every CORS origin, and returns exception details and stack traces. An attacker can obtain sensitive configuration/error information and make cross-origin requests. | Read the secret from an environment variable, restrict CORS to the local app origins, and return a generic 500 error. |
| 3 | **A04 — Cryptographic Failures** | `users.password`, `/register`, `/login`, and seeded accounts | Passwords are stored and compared in plaintext. If the database is exposed, attackers immediately obtain usable passwords. | Store passwords using a salted PBKDF2-HMAC hash and verify with `hmac.compare_digest()`. |
| 4 | **A05 — Injection** | `POST /login` | The username is directly inserted into an SQL query with an f-string. A crafted username can change the SQL statement and bypass the intended query logic. | Use a parameterized SQL query with `WHERE username = ?`. |
| 5 | **A07 — Authentication Failures** | `/login` and `current_user()` | Tokens are just user IDs, so they are predictable and do not expire. Login errors also reveal whether a username exists. An attacker can guess IDs or enumerate valid accounts. | Use signed, one-hour-expiring tokens and return one generic login error for both unknown users and wrong passwords. |
| 6 | **A10 — Exceptional Conditions** | `GET /admin/users` | The admin permission check is inside a `try/except` that catches every exception and then continues. If the check fails, the request can proceed instead of being denied. | Remove the fail-open `except` and explicitly return 403 whenever the authenticated user is not an admin. |

## Reflection

The **A01 Broken Access Control** bug would do the most damage in a real app because authentication alone does not protect data if ownership checks are missing. An attacker who obtains any valid account could read private records belonging to other users. In a larger application, the same mistake could expose confidential customer, financial, or administrative data. Access checks should therefore be enforced on every request that accesses a protected resource.
