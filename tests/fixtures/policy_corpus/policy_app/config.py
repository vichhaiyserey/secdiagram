"""Configuration values for the policy golden corpus.

The provider token below is format-valid (AKIA + 16 uppercase chars) and free
of placeholder words so it classifies as verified. The SMTP password is a
credential-shaped assignment (likely secret, review tier). The STRIPE values
use the placeholder-filtered shapes so they never surface as findings.
"""

AWS_ACCESS_KEY_ID = "AKIAQ2F7ZKPQ2FHNQ2F7"
SMTP_PASSWORD = "hunter2-staging-credential-9f3a"
STRIPE_KEY_PLACEHOLDER = "sk_live_PLACEHOLDER_EXAMPLE_NOT_REAL"
