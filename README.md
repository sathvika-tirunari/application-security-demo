# Application Security Demo

> **Educational project.** Use only on systems you own or are explicitly authorised to test.

## 1. Problem Statement
Many web vulnerabilities come from missing access control, weak validation and absent security headers. Beginners need one compact example that combines these defences.

## 2. Objective
Demonstrate login, password hashing, input validation, sessions, role-based access control (RBAC) and security headers in a small Flask app.

## 3. Features
- Registration and login with hashed passwords
- Input validation and parameterised SQL
- Session management (20-minute lifetime, session reset on login)
- Two roles: `user` and `admin`; admin-only page and role-management form
- Role re-checked from the database on every request
- Security headers: CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy
- CSRF protection on all POST requests
- Admin account created on first run with a random password shown once in the console

## 4. Technologies Used
- Python 3
- Flask
- SQLite
- Jinja2 + CSS

## 5. Folder Structure
```text
04-application-security-demo/
  .env.example
  .gitignore
  LICENSE
  README.md
  app.py
  requirements.txt
  static/style.css
  templates/admin.html
  templates/base.html
  templates/dashboard.html
  templates/error.html
  templates/index.html
  templates/login.html
  templates/register.html
```

## 6. Installation Steps
1. Install **Python 3.9 or newer** from <https://www.python.org/downloads/> (tick "Add Python to PATH" on Windows).
2. Open a terminal **inside this project folder**.
3. Create and activate a virtual environment:
   - Windows: `python -m venv venv` then `venv\Scripts\activate`
   - macOS/Linux: `python3 -m venv venv` then `source venv/bin/activate`
4. Install the dependencies: `pip install -r requirements.txt`

## 7. Commands to Run
```bash
python app.py
# First run prints: Username: admin  Password: <random>   (save it!)
# Or choose your own admin password before starting:
#   Windows (PowerShell): $env:DEMO_ADMIN_PASSWORD="YourStrongPass123"
#   macOS/Linux:          export DEMO_ADMIN_PASSWORD="YourStrongPass123"
# Open http://127.0.0.1:5000
```

## 8. How It Works
1. On first start the database is created together with an `admin` user.
2. Anyone can register, but new accounts always get the `user` role (the form cannot set a role).
3. `@role_required('admin')` looks up the current role in the database; users get **403 Forbidden**.
4. An `after_request` hook adds security headers to every response.

## 9. Example Input / Output
1. Register `bob_1` / `BobPass12345`, log in -> Dashboard shows *Your role: user*.
2. Visit `/admin` -> **Error 403** page.
3. Log in as `admin` with the console password -> `/admin` lists users and lets you change roles.
4. Try username `bob'--` at registration -> *Username must be 3-30 letters, numbers or underscores.*

## 10. Screenshots
_Add your own screenshots after running the project (do not use screenshots from elsewhere)._

| Description | Screenshot |
|---|---|
| Main screen / output | `docs/screenshot-1.png` _(placeholder)_ |
| Another feature | `docs/screenshot-2.png` _(placeholder)_ |

## 11. Demo Link
`<YOUR-DEMO-LINK-HERE>` _(placeholder: this project has not been deployed by the author of this template)_

## 12. Security Measures
- Password hashing (salted)
- Parameterised SQL (SQL injection defence)
- Server-side validation and request size limit (16 KB)
- RBAC enforced server-side on each request
- CSRF tokens; HttpOnly/SameSite cookies
- Security headers on all responses (HSTS added automatically over HTTPS)
- No hard-coded secrets; debug off by default

## 13. Limitations
- No login throttling in this demo
- No password reset or email verification
- Development server only
- CSP is strict (no inline scripts), so add JS as separate files if you extend it

## 14. Future Improvements
- Login rate limiting and lockout
- Audit log of admin actions
- Two-factor authentication
- Unit tests with pytest

## 15. GitHub Upload Instructions
1. Sign in at <https://github.com> and click **New repository** (the **+** icon, top right).
2. Name it `04-application-security-demo`, choose Public or Private, and click **Create repository**.
3. On the new repo page click **uploading an existing file**.
4. Drag in the **contents** of this folder (files and sub-folders, *not* the ZIP itself). Hidden files such as `.gitignore` must be included.
5. Write a commit message such as `Initial commit` and click **Commit changes**.
6. Edit `LICENSE` and replace `<YOUR NAME>`; add real screenshots to a `docs/` folder and update the README.

## License
MIT. See `LICENSE`.
