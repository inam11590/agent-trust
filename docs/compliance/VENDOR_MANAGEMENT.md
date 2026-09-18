# Vendor management (engineering draft)

Maintain an inventory of PostgreSQL and Redis hosting, cloud deployment, email/push services, billing sandbox or live provider, error monitoring, and each enterprise OIDC identity provider. For each vendor record an owner, purpose, data classes processed, region, access method, contractual review, incident contact, and offboarding plan.

OIDC provider configuration must be reviewed per customer: issuer, discovery URL, client ID, client secret storage, redirect URI, signing-key rotation, verified-email behavior, MFA assurance claims, and emergency owner access. Local mocked OIDC tests demonstrate code paths but do not prove interoperability with Entra ID, Okta, or Google Workspace.

Do not describe AgentTrust as certified or compliant based on these engineering documents. External audits, legal review, policies in operation, and evidence collection remain separate work.
