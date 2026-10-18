# Contributing to Nmap-NSE-Script-Collection

Thanks for your interest in contributing! This project collects **defensive, informational** Nmap NSE scripts, and every contribution must stay within that scope.

Please read the whole document before opening a pull request. Pull requests that ignore the sections on legal use, AI-generated content or licensing will be closed without review.

## Ground Rules

- Scripts must be **defensive/informational** in nature (detection and reporting only: no exploitation, no destructive actions).
- Every script must include a proper NSE header: `description`, `author`, `license`, `categories`.
- Use `categories = {"safe", "discovery"}` or `{"safe", "vuln"}` as appropriate. Never use `"intrusive"` unless clearly justified and documented.
- Follow the existing folder structure: place new scripts in the matching protocol folder (for example `HTTP/`, `SSH/`, `KUBERNETES/`), or propose a new folder if it's a new protocol. Script names must be unique across the whole collection.

## Legal and Ethical Requirements

This project exists to help defenders. Contributions that could not be used lawfully by a defender are not accepted.

- **No illegal functionality.** Scripts must not gain unauthorized access, bypass authentication, extract data they are not meant to see, damage or disrupt services, or persist on a target. No malware, no exploit payloads, no backdoors, no credential brute-forcing beyond documented, minimal default-credential checks.
- **Authorized testing only.** Test your script only against systems you own or have explicit written permission to test. Use the local targets in `docker-compose.yml` or your own lab.
- **No real targets in the repository.** Never include real hostnames, IP addresses, credentials, tokens, customer data or scan output from systems you do not own in code, documentation, issues or pull requests.
- **Bounded and safe by design.** Probes must use request budgets and timeouts, payloads must be inert, and secrets found in responses must be masked in output.
- **Document anything that writes.** A script that performs any write operation, even a reverted test against a sentinel object, must say so clearly in its description and in the folder `README.md`, and must be justified in the pull request.
- **Applicable law.** You are responsible for making sure your contribution and your testing comply with the laws of your jurisdiction and with the terms of any service or network involved.
- **Responsible disclosure.** If you find a vulnerability in a third-party product while developing a script, report it to the vendor following responsible disclosure practice. Do not publish unpatched exploit details in this repository.

## Nmap and Licensing Compliance

- Scripts must be built on the public NSE API and libraries provided by [Nmap](https://nmap.org). Follow the [Nmap documentation](https://nmap.org/book/nse.html) and the NSE conventions.
- This repository is released under the **MIT License**. By submitting a pull request you confirm that you have the right to release your contribution under the MIT License.
- Nmap and the scripts and libraries bundled with it are distributed under the **Nmap Public Source License (NPSL)**, which is not compatible with this repository's MIT License. **Do not copy or closely adapt code from Nmap's bundled scripts or libraries.** Write your own implementation, and use Nmap's libraries only through their public API.
- Do not copy code from any other project unless its license is compatible with MIT and you credit the source in the pull request.
- Do not use the Nmap name or logo in a way that suggests this project is official, endorsed by, or affiliated with the Nmap Project.

## Policy on AI-Generated Contributions

**Contributions that are generated, in whole or in part, by AI tools are strictly prohibited.** This includes code, comments, documentation, commit messages, issue text and pull request descriptions produced by large language models, AI code assistants, autocomplete agents or similar tools.

- By opening a pull request you certify that you personally wrote the contribution and that you understand every line of it.
- Maintainers may ask you to explain any part of your code or to reproduce your change interactively. A contributor who cannot explain their own submission will have the pull request closed.
- Pull requests that appear to be AI-generated will be closed without a detailed review.
- Repeated violations will result in a block from the repository.

This policy applies to contributions only. Automated security tooling that the maintainers run on the repository itself (such as CodeQL, Dependabot and secret scanning) is not affected.

## How to Contribute

1. **Fork** the repository and clone your fork locally.
2. Create a feature branch:

   ```
   git checkout -b feature/my-new-script
   ```

3. Write your script following the style of existing scripts in the same folder (see any `.nse` file for the expected structure: header comment block, `portrule`, `action` function, sample output in comments).
4. Test locally:

   ```
   nmap --script-help ./my-new-script.nse
   nmap -p <port> --script ./my-new-script.nse <test-target>
   ```

5. Run the lint gate:

   ```
   pip install lupa
   python3 tools/lint_nse.py <FOLDER>
   ```

6. Update the documentation:
   - Add your script to the folder's `README.md` (description, risk level, what it checks, usage, sample output)
   - If you add a new protocol folder, add a row to the **Categories** table in the root `README.md`
7. Commit with a clear, descriptive message:

   ```
   git commit -m "Add http-jwt-none-alg-check: detects JWT 'none' algorithm acceptance"
   ```

8. Push and open a **Pull Request** against `main`.

## Pull Request Checklist

Before submitting, confirm:

- [ ] Script runs without errors against a lab target I own or am authorized to test
- [ ] Script has a `description`, `author`, `license`, and `categories` field
- [ ] Risk level is accurately assessed (see the README's Risk Levels table)
- [ ] `python3 tools/lint_nse.py` passes
- [ ] Folder `README.md` updated (and the root `README.md` Categories table for new folders)
- [ ] No hardcoded credentials, IPs, or destructive/intrusive actions
- [ ] No real hostnames, IPs or third-party data anywhere in the change
- [ ] Any write operation is documented and justified
- [ ] I wrote this contribution myself, with no AI-generated content
- [ ] No code copied from Nmap's bundled scripts or libraries, and I can release this under the MIT License
- [ ] Code is commented where logic isn't self-explanatory

## Reporting Bugs / False Positives

Open a [GitHub Issue](https://github.com/NexzaDev/Nmap-NSE-Script-Collection/issues) with:

- The script name and Nmap version
- The exact command you ran
- Expected vs. actual output
- Target service/version if relevant (no need to disclose real hostnames/IPs)

To report a vulnerability or unsafe script behavior, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Code of Conduct

Be respectful and constructive. This is a security research and education project: keep discussions professional and focused on improving detection quality.
