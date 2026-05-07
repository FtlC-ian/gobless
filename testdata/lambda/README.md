# Lambda Compatibility Fixtures

This directory contains AWS API Gateway/Lambda event fixtures for BLESS-style certificate requests and expected sanitized error response bodies.

Event fixtures use a minimal API Gateway proxy-event shape:

- `version`
- `routeKey`
- `rawPath`
- `headers`
- `requestContext.identity` and/or `requestContext.authorizer.iam`
- `body`
- `isBase64Encoded`

Tests should decode `body` when applicable, route the request through the Lambda handler, and compare accepted fields or expected error classes. Response fixtures under `responses/` include `no_leak_assertions` strings that must not appear in serialized responses, logs, or returned error messages.
