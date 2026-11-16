<?php

declare(strict_types=1);

namespace G\FailSentryMiddleware;

use G\FailSentryMiddleware\Storage\StorageInterface;
use InvalidArgumentException;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Throwable;

class FailSentryMiddleware implements MiddlewareInterface
{
    private const int MIN_STATUS_CODE = 100;
    private const int MAX_STATUS_CODE = 599;
    private const int BITS_PER_BYTE = 8;
    private const int BYTE_MASK = 0xFF;

    /**
     * @param StorageInterface                         $storage
     *   Storage backend for failures and blocks.
     * @param ResponseFactoryInterface                 $responseFactory
     *   PSR-17 factory used to build the 429 response.
     * @param int                                      $maxAttempts
     *   Number of failures before blocking (default: 5).
     * @param int                                      $blockTtl
     *   Block duration in seconds (default: 3600).
     * @param int                                      $failureTtl
     *   Failure window in seconds (default: 3600).
     * @param int[]                                    $failureCodes
     *   HTTP status codes considered suspicious.
     * @param (\Closure(ResponseInterface): bool)|null $failureDetector
     *   Custom detector; overrides $failureCodes when set.
     * @param string[]                                 $whitelistedIps
     *   IP addresses or CIDR ranges never blocked.
     * @param string[]                                 $trustedProxies
     *   Trusted proxy IPs or CIDR ranges for header resolution.
     * @param bool                                     $failOpenOnStorageError
     *   When true (default): pass through on unresolvable IP or storage error.
     *   When false: block on any uncertainty (unresolvable IP or storage error).
     * @param bool                                     $resetOnSuccess
     *   When true: a non-failure response clears the failures of the IP, so only consecutive
     *   failures lead to a block. When false (default): failures only expire with $failureTtl,
     *   so valid requests slipped between attempts do not help an attacker.
     */
    public function __construct(
        private readonly StorageInterface $storage,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly int $maxAttempts = 5,
        private readonly int $blockTtl = 3600,
        private readonly int $failureTtl = 3600,
        private readonly array $failureCodes = [400, 401, 403, 405, 422, 429],
        private readonly \Closure|null $failureDetector = null,
        private readonly array $whitelistedIps = [],
        private readonly array $trustedProxies = [],
        private readonly bool $failOpenOnStorageError = true,
        private readonly bool $resetOnSuccess = false,
    ) {
        if ($this->maxAttempts < 1) {
            throw new InvalidArgumentException('maxAttempts must be greater than 0.');
        }

        if ($this->blockTtl < 1) {
            throw new InvalidArgumentException('blockTtl must be greater than 0.');
        }

        if ($this->failureTtl < 1) {
            throw new InvalidArgumentException('failureTtl must be greater than 0.');
        }

        foreach ($this->failureCodes as $statusCode) {
            if ($statusCode < self::MIN_STATUS_CODE || $statusCode > self::MAX_STATUS_CODE) {
                throw new InvalidArgumentException('failureCodes must only contain valid HTTP status codes.');
            }
        }
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $ip = $this->resolveIp($request);

        if ($ip === null) {
            // REMOTE_ADDR is server-set and cannot be forged directly by a client.
            // A null result indicates a severely misconfigured server or a proxy
            // chain where every candidate IP is invalid. Respect the configured
            // fail-open/fail-closed policy instead of always passing through.
            return $this->failOpenOnStorageError
                ? $handler->handle($request)
                : $this->createBlockedResponse();
        }

        if ($this->matchesAny($ip, $this->whitelistedIps)) {
            return $handler->handle($request);
        }

        $isBlocked = $this->safeIsBlocked($ip);

        if ($isBlocked === true) {
            return $this->createBlockedResponse();
        }

        if ($isBlocked === null && !$this->failOpenOnStorageError) {
            return $this->createBlockedResponse();
        }

        $response = $handler->handle($request);

        if ($this->isFailure($response)) {
            $currentFailures = $this->safeRecordFailureAndCount($ip);

            if ($currentFailures === null) {
                return $this->failOpenOnStorageError ? $response : $this->createBlockedResponse();
            }

            if ($currentFailures >= $this->maxAttempts) {
                $didBlock = $this->safeBlockIp($ip);

                if ($didBlock === false && $this->failOpenOnStorageError) {
                    return $response;
                }

                return $this->createBlockedResponse();
            }

            return $response;
        }

        if ($this->resetOnSuccess) {
            $this->safeResetFailures($ip);
        }

        return $response;
    }

    /**
     * Resolves the client IP address, reading proxy headers only when the direct
     * connection comes from a trusted proxy, to prevent IP spoofing.
     *
     * Returns null when REMOTE_ADDR is absent or not a valid IP address.
     * When behind a trusted proxy and all XFF candidates are trusted proxies or
     * invalid, falls back to X-Real-IP then to the REMOTE_ADDR of the proxy itself.
     */
    private function resolveIp(ServerRequestInterface $request): ?string
    {
        $serverParams = $request->getServerParams();
        $remoteAddrRaw = $serverParams['REMOTE_ADDR'] ?? null;
        $remoteAddr = is_string($remoteAddrRaw) ? trim($remoteAddrRaw) : '';
        $validatedRemoteAddr = $this->normalizeIp($remoteAddr);

        if ($validatedRemoteAddr === null) {
            return null;
        }

        if ($this->trustedProxies === [] || !$this->matchesAny($validatedRemoteAddr, $this->trustedProxies)) {
            return $validatedRemoteAddr;
        }

        $forwardedFor = $request->getHeaderLine('X-Forwarded-For');

        if ($forwardedFor !== '') {
            // Walk from right to left and return the first IP that is not a trusted proxy.
            $candidates = array_reverse(
                array_map(static fn (string $s): string => trim($s), explode(',', $forwardedFor))
            );

            foreach ($candidates as $candidate) {
                $normalized = $this->normalizeIp($candidate);

                if ($normalized !== null && !$this->matchesAny($normalized, $this->trustedProxies)) {
                    return $normalized;
                }
            }
        }

        $realIp = trim($request->getHeaderLine('X-Real-IP'));
        $validatedRealIp = $this->normalizeIp($realIp);

        if ($validatedRealIp !== null) {
            return $validatedRealIp;
        }

        return $validatedRemoteAddr;
    }

    /**
     * Returns true if the given IP matches any entry in the pool.
     * Entries may be exact IPs or CIDR ranges (IPv4 and IPv6).
     *
     * @param string[] $pool
     */
    private function matchesAny(string $ip, array $pool): bool
    {
        foreach ($pool as $entry) {
            $candidate = trim($entry);

            if ($candidate === '') {
                continue;
            }

            if (str_contains($candidate, '/')) {
                if ($this->matchesCidr($ip, $candidate)) {
                    return true;
                }

                continue;
            }

            $normalized = $this->normalizeIp($candidate);

            if ($normalized !== null && $ip === $normalized) {
                return true;
            }
        }

        return false;
    }

    /**
     * Tests whether an IP address falls within a CIDR range.
     * Supports both IPv4 (e.g. 10.0.0.0/8) and IPv6 (e.g. ::1/128).
     */
    private function matchesCidr(string $ip, string $cidr): bool
    {
        if (!str_contains($cidr, '/')) {
            return false;
        }

        [$network, $prefixLen] = explode('/', $cidr, 2);

        if (!ctype_digit($prefixLen)) {
            return false;
        }

        $normalizedIp = $this->normalizeIp($ip);
        $normalizedNetwork = $this->normalizeIp($network);

        if ($normalizedIp === null || $normalizedNetwork === null) {
            return false;
        }

        $prefix = (int) $prefixLen;

        $ipBin = inet_pton($normalizedIp);
        $networkBin = inet_pton($normalizedNetwork);

        if ($ipBin === false || $networkBin === false || strlen($ipBin) !== strlen($networkBin)) {
            return false;
        }

        $byteLen = strlen($ipBin);
        $maxBits = $byteLen * self::BITS_PER_BYTE;

        if ($prefix < 0 || $prefix > $maxBits) {
            return false;
        }

        $fullBytes = intdiv($prefix, self::BITS_PER_BYTE);
        $remainingBits = $prefix % self::BITS_PER_BYTE;

        if ($fullBytes > 0 && substr($ipBin, 0, $fullBytes) !== substr($networkBin, 0, $fullBytes)) {
            return false;
        }

        if ($remainingBits > 0) {
            $mask = self::BYTE_MASK & (self::BYTE_MASK << (self::BITS_PER_BYTE - $remainingBits));

            if ((ord($ipBin[$fullBytes]) & $mask) !== (ord($networkBin[$fullBytes]) & $mask)) {
                return false;
            }
        }

        return true;
    }

    private function isFailure(ResponseInterface $response): bool
    {
        if ($this->failureDetector !== null) {
            return ($this->failureDetector)($response);
        }

        return in_array($response->getStatusCode(), $this->failureCodes, true);
    }

    private function createBlockedResponse(): ResponseInterface
    {
        $response = $this->responseFactory->createResponse(429);

        return $response
            ->withHeader('Retry-After', (string) $this->blockTtl)
            ->withHeader('Cache-Control', 'no-store');
    }

    /**
     * Validates an IP address and returns its canonical form, so that the same address
     * always gives the same string (e.g. "0:0:0:0:0:0:0:1" and "::1").
     */
    private function normalizeIp(string $ip): ?string
    {
        $trimmed = trim($ip);

        if ($trimmed === '' || filter_var($trimmed, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $binary = inet_pton($trimmed);
        $canonical = $binary !== false ? inet_ntop($binary) : false;

        return $canonical !== false ? $canonical : null;
    }

    private function safeIsBlocked(string $ip): ?bool
    {
        try {
            return $this->storage->isBlocked($ip);
        } catch (Throwable) {
            return null;
        }
    }

    private function safeRecordFailureAndCount(string $ip): ?int
    {
        try {
            $this->storage->addFailure($ip, $this->failureTtl);

            return $this->storage->countFailures($ip);
        } catch (Throwable) {
            return null;
        }
    }

    private function safeBlockIp(string $ip): bool
    {
        try {
            $this->storage->blockIp($ip, $this->blockTtl);

            return true;
        } catch (Throwable) {
            return false;
        }
    }

    private function safeResetFailures(string $ip): void
    {
        try {
            $this->storage->resetFailures($ip);
        } catch (Throwable) {
            // Ignore storage reset failures to preserve request flow.
        }
    }
}
