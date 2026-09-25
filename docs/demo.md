# Demo and screenshots

## Preparing demo data honestly

Findings must come from a real scan. Two ways:

- **A real (lab) AWS account**, best: create a deliberately weak setup in a sandbox account,
  for example a security group with SSH open to `0.0.0.0/0` (not attached to anything), an S3
  bucket without Block Public Access, an IAM user with a console password and no MFA. Scan it,
  then **delete those resources**. Set an AWS Budget alert first.
- **Without AWS: sandbox mode** ([sandbox.md](sandbox.md)). The real app scans a simulated AWS
  account, and the Sandbox page lets you break or fix one setting per rule live. Always say it
  is simulated (the app shows a banner); do not present it as a real account.

Never demo against an account you are not authorized to scan.

## Demo checklist (about 5 minutes)

1. **Architecture in one sentence:** React → nginx → FastAPI → PostgreSQL, with boto3
   read-only calls to AWS. Mention the collect → normalize → rules → risk → findings pipeline.
2. **Sign in** as ADMIN; point out there is no public sign-up.
3. **Settings → AWS accounts:** show *Verify access* (the scan refuses if the credentials belong
   to another account). Mention that no credentials are stored.
4. **Scans:** start a scan, show the status updating, open it: coverage per service and the
   per-rule results (*Passed / Failed / Incomplete*).
5. **Dashboard:** overall risk (the worst open finding), severity and category charts, top risks.
6. **Finding details:** evidence (raw facts), risk explanation (points per factor),
   remediation, detection rule and its limitations.
7. **Triage as ANALYST:** acknowledge a finding with a note; mark a false positive (a note is
   required).
8. **Fix it in AWS and re-scan:** the finding closes automatically. Then explain why a
   finding is never closed when a check could not run.
9. **Audit log** as ADMIN: the sign-ins, the scan and the triage you just did; mention that the
   database refuses to change or delete these rows.
10. **Sign in as VIEWER:** no scan or triage controls; the API would refuse anyway (403,
    recorded in the audit log).
11. **CI:** show a green GitHub Actions run: tests, audits, secret scan, Docker hardening checks.

## Screenshots checklist

Take them at 1280 px wide, with realistic data from a lab account (no real account IDs you do
not want to publish; blur them if needed).

- [ ] Sign-in page
- [ ] Dashboard with findings (overall risk, charts, top risks)
- [ ] Dashboard empty state ("No scans yet")
- [ ] Findings list with a filter applied (e.g. High + Critical)
- [ ] Finding details: evidence and risk explanation
- [ ] Finding details: remediation and triage form
- [ ] Scan details of a *Completed with errors* scan (coverage + Incomplete rules)
- [ ] Scans list with a running scan
- [ ] Resources list and one resource's configuration
- [ ] Settings: AWS accounts with a successful *Verify access*
- [ ] Audit log with a failed login and an access-denied event
- [ ] Users page (role controls)
- [ ] Phone-width view of the dashboard
- [ ] `/api/docs` (Swagger UI) with the tag list
- [ ] GitHub Actions run with all four jobs green
