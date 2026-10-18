# Contributing to Nmap-NSE-Script-Collection

Thanks for your interest in contributing! This project collects **defensive, informational** Nmap NSE scripts, and every contribution should stay within that scope.

## Ground Rules

- Scripts must be **defensive/informational** in nature (detection and reporting only — no exploitation, no destructive actions).
- Every script must include a proper NSE header: `description`, `author`, `license`, `categories`.
- Use `categories = {"safe", "discovery"}` or `{"safe", "vuln"}` as appropriate — never `"intrusive"` unless clearly justified and documented.
- Follow the existing folder structure: place new scripts in the matching protocol folder (for example `HTTP/`, `SSH/`, `KUBERNETES/`), or propose a new folder if it's a new protocol. Script names must be unique across the whole collection.

## How to Contribute

1. **Fork** the repository and clone your fork locally.
2. Create a feature branch:
   ```bash
   git checkout -b feature/my-new-script
   ```
3. Write your script following the style of existing scripts in the same folder (see any `.nse` file for the expected structure: header comment block, `portrule`, `action` function, sample output in comments).
4. Test locally:
   ```bash
   nmap --script-help ./my-new-script.nse
   nmap -p <port> --script ./my-new-script.nse <test-target>
   ```
5. Run the lint gate:
   ```bash
   pip install lupa
   python3 tools/lint_nse.py <FOLDER>
   ```
6. Update the documentation:
   - Add your script to the folder's `README.md` (description, risk level, what it checks, usage, sample output)
   - If you add a new protocol folder, add a row to the **Categories** table in the root `README.md`
7. Commit with a clear, descriptive message:
   ```bash
   git commit -m "Add http-jwt-none-alg-check: detects JWT 'none' algorithm acceptance"
   ```
8. Push and open a **Pull Request** against `main`.

## Pull Request Checklist

Before submitting, confirm:

- [ ] Script runs without errors against a real or lab target
- [ ] Script has a `description`, `author`, `license`, and `categories` field
- [ ] Risk level is accurately assessed (see the README's Risk Levels table)
- [ ] `python3 tools/lint_nse.py` passes
- [ ] Folder `README.md` updated (and the root `README.md` Categories table for new folders)
- [ ] No hardcoded credentials, IPs, or destructive/intrusive actions
- [ ] Code is commented where logic isn't self-explanatory

## Reporting Bugs / False Positives

Open a [GitHub Issue](../../issues) with:
- The script name and Nmap version
- The exact command you ran
- Expected vs. actual output
- Target service/version if relevant (no need to disclose real hostnames/IPs)

## Code of Conduct

Be respectful and constructive. This is a security research/education project — keep discussions professional and focused on improving detection quality.
