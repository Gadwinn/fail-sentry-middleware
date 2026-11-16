<?php

declare(strict_types=1);

namespace G\FailSentryMiddleware\Storages;

interface StorageInterface
{
    /**
     * Determine whether the given IP address is currently blocked.
     */
    public function isBlocked(string $ip): bool;

    /**
     * Record a new failure event for the given IP address.
     *
     * @param int $ttl Failure window duration in seconds. The failure is discarded after this delay.
     */
    public function addFailure(string $ip, int $ttl): void;

    /**
     * Return the number of non-expired failures recorded for the given IP address.
     */
    public function countFailures(string $ip): int;

    /**
     * Block the given IP address for the specified duration.
     *
     * @param int $ttl Block duration in seconds.
     */
    public function blockIp(string $ip, int $ttl): void;

    /**
     * Remove all failure records for the given IP address.
     */
    public function resetFailures(string $ip): void;
}
