# auth-template - Changelog

## 2.0.0

- Require IAM 5 and crypto 1.2.
- Return principal/null from authenticate; use typed exchange rejection/block
  errors while preserving operational failures and lockout delays.
- Add real-driver REST/RBAC integration and protection-contract coverage.
