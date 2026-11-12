# care-it-backend

## Render environment

Set `JWT_EXPIRE=30d` in the deployed backend environment so authenticated sessions survive up to thirty days. A deliberate sign out still clears the browser session immediately.

## Password reset email setup

Configure these environment variables in Render for Brevo email delivery:

- `BREVO_API_KEY`: Brevo API key with transactional email access.
- `BREVO_SENDER_EMAIL`: a sender email verified in Brevo.
- `BREVO_SENDER_NAME`: optional sender name, such as `CARE IT Asset Management`.

The password-reset OTP uses Brevo's `POST /v3/smtp/email` API. Do not commit the API key or any email password to the repository.

## Consumables stock API

The authenticated Utilities workspace uses `GET /api/consumables?year=YYYY` to read
the catalogue and monthly movements. Admins can add or update catalogue items with
`POST /api/consumables` and `PUT /api/consumables/:id`. Users and admins record
monthly receipts or issues with `POST /api/consumables/:id/stock`. The default
catalogue is inserted when the database connects without replacing existing items.
The corrected Supa Brite names are migrated in place so their stock movements remain linked.