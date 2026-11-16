# FailSentryMiddleware

`FailSentryMiddleware` is a PSR-15 middleware that detects suspicious HTTP outcomes and temporarily blocks abusive IP addresses, inspired by fail2ban-like behavior.

## Features

- PSR-15 compliant middleware (`MiddlewareInterface`)
- Pluggable storage backend via `StorageInterface`
- Built-in file storage implementation with file locking (`FileStorage`)
- Temporary blocks with TTL (`blockTtl`)
- Failure window with TTL (`failureTtl`)
- Configurable suspicious status codes and custom failure detector callback
- Trusted proxy support with secure client IP resolution
- Whitelist support for static IPs and CIDR ranges
- Configurable storage error policy (`fail-open` or `fail-closed`)

## Requirements

- PHP >= 8.3
- A PSR-17 response factory (any implementation)

## Installation

```bash
composer require gadwinn/fail-sentry-middleware
```

## Quick Start

```php
<?php

declare(strict_types=1);

use G\FailSentryMiddleware\FailSentryMiddleware;
use G\FailSentryMiddleware\Storages\FileStorage;
$storage = new FileStorage(__DIR__ . '/var/fail-sentry.json');
$responseFactory = /* any PSR-17 ResponseFactoryInterface */;

$middleware = new FailSentryMiddleware(
	storage: $storage,
	responseFactory: $responseFactory,
	maxAttempts: 5,
	blockTtl: 3600,
	failureTtl: 900,
	failureCodes: [400, 401, 403, 405, 422, 429],
	whitelistedIps: ['127.0.0.1', '10.0.0.0/8'],
	trustedProxies: ['192.168.1.10', '172.16.0.0/12'],
	failOpenOnStorageError: true,
	resetOnSuccess: false,
);
```

## Stacking Multiple Sentries

You can stack several `FailSentryMiddleware` instances in your PSR-15 pipeline to enforce independent policies per status code. Each instance must use its own storage file so that failure counters remain isolated.

```php
<?php

declare(strict_types=1);

use G\FailSentryMiddleware\FailSentryMiddleware;
use G\FailSentryMiddleware\Storages\FileStorage;
$responseFactory = /* any PSR-17 ResponseFactoryInterface */;

// Aggressive rate-limit abuse: block after 5 × 429 within 15 minutes
$sentryRateLimit = new FailSentryMiddleware(
	storage: new FileStorage(__DIR__ . '/var/fail-sentry-429.json'),
	responseFactory: $responseFactory,
	maxAttempts: 5,
	blockTtl: 3600,
	failureTtl: 900,
	failureCodes: [429],
);

// Scanning/enumeration: block after 20 × 404 within 15 minutes
$sentryScanner = new FailSentryMiddleware(
	storage: new FileStorage(__DIR__ . '/var/fail-sentry-404.json'),
	responseFactory: $responseFactory,
	maxAttempts: 20,
	blockTtl: 3600,
	failureTtl: 900,
	failureCodes: [404],
);

// Broad catch-all: block after 50 auth/validation failures within 1 hour
$sentryCatchAll = new FailSentryMiddleware(
	storage: new FileStorage(__DIR__ . '/var/fail-sentry-auth.json'),
	responseFactory: $responseFactory,
	maxAttempts: 50,
	blockTtl: 86400,
	failureTtl: 3600,
	failureCodes: [401, 403, 422],
);

// Add all three to your middleware pipeline (order: strictest first)
$app->pipe($sentryRateLimit);
$app->pipe($sentryScanner);
$app->pipe($sentryCatchAll);
```

> Each sentry tracks failures independently. An IP blocked by one sentry is not automatically blocked by the others.

## How Failure Detection Works

By default, a request is considered suspicious when the response status code is in `failureCodes`.

You can override this with a custom detector:

```php
$middleware = new FailSentryMiddleware(
	storage: $storage,
	responseFactory: $responseFactory,
	failureDetector: static fn (\Psr\Http\Message\ResponseInterface $response): bool =>
		$response->getStatusCode() >= 400,
);
```

## Security Notes

- Client IP is resolved from `REMOTE_ADDR` by default.
- Proxy headers (`X-Forwarded-For`, `X-Real-IP`) are used only when `REMOTE_ADDR` is a trusted proxy.
- Invalid IP values are ignored to reduce spoofing and malformed input risks.
- IP addresses are compared and stored in canonical form (`0:0:0:0:0:0:0:1` and `::1` are the same address).
- Failures expire with `failureTtl` only: a valid request slipped between attempts does not clear them. Pass `resetOnSuccess: true` to count *consecutive* failures instead (friendlier, but easier to evade).
- `404` is not a failure by default (a missing favicon or a dead link would block ordinary visitors): add it to `failureCodes` in a dedicated sentry with a high `maxAttempts` to catch scanners, as shown above.
- Blocked responses return `429` with `Retry-After` and `Cache-Control: no-store` headers.

## Storage Backend Contract

Any backend must implement:

- `isBlocked(string $ip): bool`
- `addFailure(string $ip, int $ttl): void`
- `countFailures(string $ip): int`
- `blockIp(string $ip, int $ttl): void`
- `resetFailures(string $ip): void`

`FileStorage` keeps everything in one JSON file protected by an exclusive lock. Expired failures and blocks are dropped at each write, and the file is only written when something changes. It suits small to medium traffic; implement `StorageInterface` (Redis, APCu…) for more.

## Development

```bash
composer test-all
```
