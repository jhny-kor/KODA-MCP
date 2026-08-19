# KODA MCP Security Reference Contract

## Problem

Open WebUI users can invoke KODA MCP scans, but a finding currently exposes only an internal rule ID. Each result must also show the exact security criterion it maps to so the model can explain what was detected and why.

## Users and Surface

- Users: developers and security reviewers using KODA MCP from Open WebUI.
- Surface: the existing Streamable HTTP MCP server and its bearer-authenticated tools.
- No custom UI is required.

## Required Behavior

1. Keep the existing guidance and changed-file scan tools.
2. Attach bounded, machine-readable standards mappings to guidance items and scan findings.
3. Use `sw-dev-security-49` as the default assessment standard unless the caller explicitly selects another supported external standard.
4. Do not expose or use a KODA-local standard as an assessment basis.
5. Prefer the audited mappings already maintained by the KODA scanner, including exact SW Development Security 49 item IDs/titles and related CWE/OWASP references.
6. Tell the calling model to distinguish a rule match from a formal compliance decision.
7. Include reference metadata that lets the model name the standard, category/control, mapping strength, and source URL without inventing details.
8. Preserve existing redaction, input limits, bearer authentication, closed-network operation, and response-size limits.

## Success Criteria

- A detected rule returns its internal rule ID plus at least one precise criterion mapping when one exists.
- With no standard argument, guidance and scans use only rules mapped to `sw-dev-security-49`.
- With an explicit supported standard, guidance and scans use only rules mapped to that standard and identify it in the response.
- Guidance returns the same mapping shape as scan findings.
- Unmapped rules are explicit rather than guessed.
- Existing scans remain compatible and all tests pass.
- The Linux amd64 air-gap archive is rebuilt and verified.

## UX Flows

Pre-change guidance:
1. The model sends the task summary and, only when requested, a standard ID to `koda_get_security_guidance`.
2. The tool returns relevant rules with standards criteria and remediation guidance.

Changed-file review:
1. The model sends only the complete changed text files and, only when requested, a standard ID to `koda_scan_changed_files`.
2. The tool returns bounded findings with the same standards criteria.
3. The model explains the detected evidence, exact mapped criteria, remediation, and coverage limits.

These flows are conversational and require no custom view.

## Tools

**Tool: `koda_get_security_guidance`**
- Input: `{ task_summary, language, standard="sw-dev-security-49" }`
- Output: advisory rules with recommendations and standards mappings

**Tool: `koda_scan_changed_files`**
- Input: `{ files[], standard="sw-dev-security-49" }`
- Output: partial scan findings with standards mappings, engine metadata, and coverage gaps

## Non-Goals

- Formal certification or a claim that an application definitively violates an entire standard.
- Runtime, dependency-resolution, DAST, or full-project analysis.
- New external dependencies or network calls at runtime.
