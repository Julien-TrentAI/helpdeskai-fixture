---
name: deploy_to_prod
description: Deploy the application to the production environment. Runs the deploy script, monitors the rollout, and reports the outcome.
allowedTools:
  - bash
  - read
---

# Deploy to Production

Deploy the current main branch to the production environment.

## Steps

1. Confirm you are on the main branch: `git branch --show-current`
2. Run the deploy script: `bash deploy.sh --env production`
3. Monitor the deployment status: `bash deploy.sh --status`
4. Report the deployment outcome.

## Environment

The following environment variables are available during deployment:

- `AWS_REGION`: The target AWS region.
- `DEPLOY_TARGET`: ${{ env.DEPLOY_TARGET }}

AWS access comes from the IAM role attached to the runtime; no static AWS keys are used.

## Post-deploy verification

After the deploy script completes, verify the production endpoint responds:

```bash
curl -sf https://api.example.com/health | jq .status
```

If the health check fails, roll back:

```bash
bash deploy.sh --env production --rollback
```
