# Tests

The pipeline tests compare the output of the streaming refactor against a set
of golden files produced by the legacy code. Because both the fixture log and
the golden files are derived from real ZPA traffic and contain client PII
(usernames, IPs, hostnames), they are **not tracked in git** — see the project
rule "No privileged information in tracked files" in CLAUDE.md.

## Regenerate fixtures and golden files locally

Place a real (or anonymised) gzipped ZPA log under `logs/`, then:

```bash
mkdir -p tests/fixtures tests/golden

# Extract ~2000 zapp records into the fixture
gunzip -c logs/zpa.log-YYYYMMDD.gz \
    | grep -F '"ClientType": "zpn_client_type_zapp"' \
    | head -2000 > tests/fixtures/sample_small.log

# Generate the golden reports from the fixture using the CURRENT code
# (run this BEFORE any pipeline refactor so the golden captures the
# reference behaviour)
PYTHONPATH=src ZPA_SIEM_CONFIG=config.ini .venv/bin/python3 src/report_generator.py \
    --log-file tests/fixtures/sample_small.log \
    --output-dir tests/golden \
    --date YYYY-MM-DD \
    --no-upload

# Rename outputs to the names the tests expect
cd tests/golden && \
    mv zpa-report-YYYY-MM-DD.csv  sample_small.csv && \
    mv zpa-report-YYYY-MM-DD.json sample_small.json && \
    mv zpa-report-YYYY-MM-DD.xlsx sample_small.xlsx
```

The `YYYY-MM-DD` must match the `REPORT_DATE` constant in
`tests/test_equivalence.py` (currently `2026-04-19`).

## Run the suite

```bash
.venv/bin/python3 -m pytest tests/ -v
```

If `tests/fixtures/sample_small.log` is missing, the equivalence tests will
fail at the subprocess call. The legacy-vs-streaming tests
(`test_session_acc_uses_slots`, `test_report_columns_unchanged`) run without
fixtures.
