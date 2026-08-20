# KODA MCP Security Reference Contract

## Problem

Open WebUI users can invoke KODA MCP scans, but each result must show both the exact mapped security criterion and the redacted source line that triggered the finding so the model can explain what was detected, where, and why.

## Users and Surface

- Users: developers and security reviewers using KODA MCP from Open WebUI.
- Surface: the existing Streamable HTTP MCP server and its bearer-authenticated tools.
- No custom UI is required.

## Required Behavior

1. Keep the existing guidance and changed-file scan tools.
2. Attach bounded, machine-readable standards mappings to guidance items and scan findings.
3. Use `sw-dev-security-49` as the default assessment standard unless the caller explicitly selects another supported external standard.
4. Support `standard="all"` as an explicit opt-in that preserves every KODA core finding and attaches every supported standards mapping.
5. Do not expose or use a KODA-local standard as an assessment basis.
6. Use the copied KODA core checks without suppressing or rewriting their vulnerability findings.
7. Prefer the audited mappings already maintained by the KODA scanner, including exact SW Development Security 49 item IDs/titles and related CWE/OWASP references.
8. Tell the calling model to distinguish a rule match from a formal compliance decision.
9. Include reference metadata that lets the model name the standard, category/control, mapping strength, and source URL without inventing details.
10. Preserve existing redaction, input limits, bearer authentication, closed-network operation, and response-size limits.
11. Return each detected location as a separate finding with its line range, secret-redacted snippet, reason, and recommendation.
12. Tell the calling model to render every returned finding separately with problem code, criterion, reason, and corrected example; never reconstruct redacted values.

## Success Criteria

- A detected rule returns its internal rule ID plus at least one precise criterion mapping when one exists.
- With no standard argument, guidance and scans use only rules mapped to `sw-dev-security-49`.
- With an explicit supported standard, guidance and scans use only rules mapped to that standard and identify it in the response.
- With `standard="all"`, scans preserve every KODA core finding and every available mapping; guidance returns every available mapping for its rules.
- MCP redaction and transport limits do not change KODA rule matching or suppress a KODA finding.
- Guidance returns the same mapping shape as scan findings.
- Every returned line-level finding includes `start_line`, `end_line`, `redacted_snippet`, and `reason`.
- Multiple detected lines remain separate findings and the model is instructed not to group or omit them.
- Known secret values in snippets are replaced with `<redacted>` and never returned verbatim.
- Unmapped rules are explicit rather than guessed.
- Existing scans remain compatible and all tests pass.
- The Linux amd64 air-gap archive is rebuilt and verified.

## UX Flows

Pre-change guidance:
1. The model sends the task summary and, only when requested, a standard ID or `all` to `koda_get_security_guidance`.
2. The tool returns relevant rules with standards criteria and remediation guidance.

Changed-file review:
1. The model sends only the complete changed text files and, only when requested, a standard ID or `all` to `koda_scan_changed_files`.
2. The tool returns bounded findings with the same standards criteria.
3. The tool returns every detected location separately with a redacted source snippet.
4. The model renders one section per finding with problem code, exact mapped criterion, reason, remediation, corrected example, and coverage limits.

These flows are conversational and require no custom view.

## Tools

**Tool: `koda_get_security_guidance`**
- Input: `{ task_summary, language, standard="sw-dev-security-49" }`
- Output: advisory rules with recommendations and standards mappings

**Tool: `koda_scan_changed_files`**
- Input: `{ files[], standard="sw-dev-security-49" }`
- Output: partial scan findings with one redacted source location per finding, standards mappings, engine metadata, and coverage gaps

## Non-Goals

- Formal certification or a claim that an application definitively violates an entire standard.
- Runtime, dependency-resolution, DAST, or full-project analysis.
- New external dependencies or network calls at runtime.
- Returning complete source files or unredacted secrets in tool output.
