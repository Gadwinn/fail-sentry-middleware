<?php

declare(strict_types=1);

namespace G\FailSentryMiddleware\Storage;

use JsonException;
use RuntimeException;

/**
 * @phpstan-type StorageData array{
 *     failures: array<string, list<int>>,
 *     blocked: array<string, int>
 * }
 */
class FileStorage implements StorageInterface
{
    public function __construct(private readonly string $filePath)
    {
    }

    public function isBlocked(string $ip): bool
    {
        $handle = $this->openLocked();

        try {
            $data = $this->readData($handle);

            return isset($data['blocked'][$ip]);
        } finally {
            $this->release($handle);
        }
    }

    public function addFailure(string $ip, int $ttl): void
    {
        $handle = $this->openLocked();

        try {
            $data = $this->readData($handle);

            if (!isset($data['failures'][$ip])) {
                $data['failures'][$ip] = [];
            }

            $data['failures'][$ip][] = time() + $ttl;
            $this->writeData($handle, $data);
        } finally {
            $this->release($handle);
        }
    }

    public function countFailures(string $ip): int
    {
        $handle = $this->openLocked();

        try {
            return count($this->readData($handle)['failures'][$ip] ?? []);
        } finally {
            $this->release($handle);
        }
    }

    public function blockIp(string $ip, int $ttl): void
    {
        $handle = $this->openLocked();

        try {
            $data = $this->readData($handle);
            $data['blocked'][$ip] = time() + $ttl;
            $this->writeData($handle, $data);
        } finally {
            $this->release($handle);
        }
    }

    public function resetFailures(string $ip): void
    {
        $handle = $this->openLocked();

        try {
            $data = $this->readData($handle);

            // Called on every successful request: only write when there is something to remove.
            if (isset($data['failures'][$ip])) {
                unset($data['failures'][$ip]);
                $this->writeData($handle, $data);
            }
        } finally {
            $this->release($handle);
        }
    }

    /**
     * Opens the storage file with an exclusive lock and returns the file handle.
     *
     * @return resource
     */
    private function openLocked(): mixed
    {
        $dir = dirname($this->filePath);

        // @mkdir suppresses the OS-level warning when the directory cannot be created;
        // the final !is_dir() check ensures we still throw when it truly fails.
        if (!is_dir($dir) && !@mkdir($dir, 0o755, true) && !is_dir($dir)) {
            throw new RuntimeException(sprintf('Cannot create storage directory: %s', $dir));
        }

        $handle = @fopen($this->filePath, 'c+');

        if ($handle === false) {
            throw new RuntimeException(sprintf('Cannot open storage file: %s', $this->filePath));
        }

        if (!flock($handle, LOCK_EX)) {
            fclose($handle);
            throw new RuntimeException(sprintf('Cannot lock storage file: %s', $this->filePath));
        }

        return $handle;
    }

    /**
     * Reads and JSON-decodes the storage data from the file handle.
     * Expired failures and blocks (of every IP) are left out, so the file never keeps growing:
     * they disappear from it at the next write.
     *
     * @param  resource    $handle
     * @return StorageData
     */
    private function readData(mixed $handle): array
    {
        rewind($handle);
        $content = stream_get_contents($handle);

        if ($content === false || $content === '') {
            return $this->emptyData();
        }

        try {
            $decoded = json_decode($content, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return $this->emptyData();
        }

        return $this->normalizeData($decoded);
    }

    /**
     * @param mixed $decoded
     * @return StorageData
     */
    private function normalizeData(mixed $decoded): array
    {
        if (!is_array($decoded)) {
            return $this->emptyData();
        }

        $rawFailures = $decoded['failures'] ?? null;
        $rawBlocked = $decoded['blocked'] ?? null;

        $now = time();
        $failures = [];

        if (is_array($rawFailures)) {
            foreach ($rawFailures as $ip => $entries) {
                if (!is_string($ip) || !is_array($entries)) {
                    continue;
                }

                $normalizedEntries = [];

                foreach ($entries as $expiry) {
                    if (is_int($expiry) && $expiry > $now) {
                        $normalizedEntries[] = $expiry;
                    }
                }

                if ($normalizedEntries !== []) {
                    $failures[$ip] = $normalizedEntries;
                }
            }
        }

        $blocked = [];

        if (is_array($rawBlocked)) {
            foreach ($rawBlocked as $ip => $expiresAt) {
                if (is_string($ip) && is_int($expiresAt) && $expiresAt > $now) {
                    $blocked[$ip] = $expiresAt;
                }
            }
        }

        return [
            'failures' => $failures,
            'blocked' => $blocked,
        ];
    }

    /**
     * @return StorageData
     */
    private function emptyData(): array
    {
        return [
            'failures' => [],
            'blocked' => [],
        ];
    }

    /**
     * JSON-encodes and writes the storage data back to the file handle.
     *
     * @param resource    $handle
     * @param StorageData $data
     */
    private function writeData(mixed $handle, array $data): void
    {
        ftruncate($handle, 0);
        rewind($handle);

        try {
            $payload = json_encode($data, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT);
        } catch (JsonException $exception) {
            throw new RuntimeException('Cannot encode storage payload to JSON.', previous: $exception);
        }

        if (fwrite($handle, $payload) === false) {
            throw new RuntimeException(sprintf('Cannot write storage file: %s', $this->filePath));
        }
    }

    /**
     * Releases the exclusive lock and closes the file handle.
     *
     * @param resource $handle
     */
    private function release(mixed $handle): void
    {
        flock($handle, LOCK_UN);
        fclose($handle);
    }
}
