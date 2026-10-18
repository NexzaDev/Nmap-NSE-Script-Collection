# Tools

Development utilities for the NSE collection. Both require Python 3 and [`lupa`](https://pypi.org/project/lupa/) (`pip install lupa`); no Nmap installation is needed.

| Tool | Purpose |
|---|---|
| `lint_nse.py` | Quality gate: Lua syntax check, mandatory NSE metadata, `Risk Level` output field. `python3 tools/lint_nse.py [FOLDER ...]` |
| `smoke_nse.py` | Runs scripts inside a Lua sandbox with mocked NSE libraries and a synthetic target, printing each script's output. `python3 tools/smoke_nse.py HTTP` |
| `smoke_mocks.py`, `smoke_mocks2.py` | Mock NSE library implementations used by `smoke_nse.py` |
