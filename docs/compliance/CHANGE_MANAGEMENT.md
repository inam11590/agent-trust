# Change management (engineering draft)

Every security-sensitive change should link a reviewed change record, migration plan, tests, rollback plan, and deployment evidence. Database migrations are versioned with Alembic. Apply them in staging before production. Changes to permission, risk, organization policy, session, MFA, and SSO enforcement need negative tests proving weaker rules cannot override a denial.

Keep production secrets out of source control and pull requests. Run the repository secret scan, backend tests, web lint/type checks/tests/build, and Flutter analyze/tests as applicable. Record any failed check, fix, and rerun. A passing automated suite does not replace manual provider and deployment review.
