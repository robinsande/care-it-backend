# care-it-backend

## Password reset email setup

Configure these environment variables in Render for Brevo email delivery:

- `BREVO_API_KEY`: Brevo API key with transactional email access.
- `BREVO_SENDER_EMAIL`: a sender email verified in Brevo.
- `BREVO_SENDER_NAME`: optional sender name, such as `CARE IT Asset Management`.

The password-reset OTP uses Brevo's `POST /v3/smtp/email` API. Do not commit the API key or any email password to the repository.