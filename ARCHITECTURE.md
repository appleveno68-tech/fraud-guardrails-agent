# Production-shaped architecture

```text
Dashboard (static HTML)
        |
        v
API Gateway -> Lambda InterventionHandler
                   |-- deterministic risk signals + explainability
                   |-- Amazon Bedrock warning generation
                   |-- DynamoDB audit trail
                   `-- Amazon SNS OTP identity verification
```

The local `app.py` is a laptop fallback for the same API contract. `template.yaml` deploys the AWS path using SAM. The decision is made server-side; the browser only submits transaction facts and renders the returned decision.

## What makes the demo credible

- The evaluator enters or submits transaction facts; they never choose Approved/Blocked.
- Every decision includes `riskScore`, `riskSignals`, model message, transaction ID, and timestamp.
- Every event is auditable in DynamoDB after deployment.
- Bedrock is used for the natural-language explanation, while the deterministic guardrail remains the safety boundary.
- SNS OTP is a real identity-verification channel; configure a verified number, and observe SMS Sandbox limits for new AWS accounts.

## Deployment outline

```text
sam build
sam deploy --guided
```

Set `VERIFICATION_PHONE_NUMBER` and ensure the deployed Lambda role can invoke the selected Bedrock model and publish to SNS. Never commit AWS keys to the repository.
