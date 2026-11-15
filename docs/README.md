# CertiVault — Documentation

This folder is the complete technical documentation for **CertiVault**, a
digital certificate issuance and public verification platform built with
PHP, MySQL/MariaDB, HTML, CSS and JavaScript (Web Technology course
project).

Read the documents in order the first time; afterwards use them as a
reference.

| # | Document | What it covers |
|---|----------|----------------|
| 01 | [Project Overview](01_PROJECT_OVERVIEW.md) | Problem, solution, roles, end-to-end methodology (issuance → verification → lifecycle), verdicts, tech stack |
| 02 | [Architecture](02_ARCHITECTURE.md) | Directory layout, layers, request flow, every page and service, external libraries |
| 03 | [Database](03_DATABASE.md) | All 15 tables, relationships, indexes, the 16 migrations and when to run them |
| 04 | [Security & Cryptography](04_SECURITY_AND_CRYPTOGRAPHY.md) | Canonical hash, RSA signatures, key storage, verification cascade, threat model, all security controls, known limitations |
| 05 | [Features & User Guide](05_FEATURES_AND_USER_GUIDE.md) | What each role can do, step-by-step; Smart Verify, trust score, PDF report, status API, external sources, attested credentials, transparency log |
| 06 | [Setup & Configuration](06_SETUP_AND_CONFIGURATION.md) | Installation (XAMPP / built-in server), every configuration constant, email/SMTP, demo data, CLI scripts, troubleshooting, production checklist |
| 07 | [Testing](07_TESTING.md) | Automated CLI suites, browser tests, how to run them, current results |
| 08 | [Research Summary](08_RESEARCH_SUMMARY.md) | Summary of the accompanying IEEE-style research paper: research questions, evaluation and results |
| 09 | [Status & Roadmap](09_STATUS_AND_ROADMAP.md) | What is done, known bugs and gaps, and the prioritised next steps |
| — | [Requirements Matrix](REQUIREMENTS_MATRIX.md) | Course requirement → where it is implemented |
| — | [Manual Test Plan](TEST_PLAN.md) | Manual / end-to-end test cases with expected results |
| — | [Project Brief (PDF)](reference/CertiVault_Project_Brief.pdf) | Original 4-page brief describing the purpose and methodology |

> `docs/private/` is git-ignored. It holds the draft research paper, which
> includes author contact details and stays local until it is published.
