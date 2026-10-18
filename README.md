# FastAPI RS256 JWT verifier

Implements `POST /verify` for the assigned mock identity provider.

## Request
```json
{"token":"<JWT string>"}
```

## Valid response (HTTP 200)
```json
{"valid":true,"email":"...","sub":"...","aud":"tds-24rnhjci.apps.exam.local"}
```

## Invalid response (HTTP 401)
```json
{"valid":false}
```

The endpoint accepts only RS256, verifies the signature against the provided public key, and validates `exp`, exact issuer, and exact audience. It also requires `sub` and `email` claims because the successful response must echo them.

## Deploy on Render
1. Put `app.py`, `requirements.txt`, and `render.yaml` in a GitHub repository.
2. In Render, choose **New + → Blueprint**, connect the repository, and deploy.
3. Copy the public service URL and append `/verify`.

## Test after deployment
```bash
curl -i -X POST 'https://YOUR-SERVICE.onrender.com/verify' \
  -H 'Content-Type: application/json' \
  -d '{"token":"not-a-real-token"}'
```
This should return HTTP 401 and `{"valid":false}`. Use grader-issued tokens to test successful validation.
