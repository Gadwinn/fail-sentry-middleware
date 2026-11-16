<?php

declare(strict_types=1);

namespace G\FailSentryMiddleware\Tests\Storage;

use G\FailSentryMiddleware\Storage\FileStorage;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class FileStorageTest extends TestCase
{
    private string $tempFile;
    private FileStorage $storage;

    protected function setUp(): void
    {
        // Create a unique temp path but do not create the file - FileStorage must create it.
        $this->tempFile = tempnam(sys_get_temp_dir(), 'fail_sentry_test_') . '.json';
        $this->storage = new FileStorage($this->tempFile);
    }

    protected function tearDown(): void
    {
        if (file_exists($this->tempFile)) {
            unlink($this->tempFile);
        }
    }

    // -------------------------------------------------------------------------
    // isBlocked
    // -------------------------------------------------------------------------

    public function testIsBlockedReturnsFalseForUnknownIp(): void
    {
        $this->assertFalse($this->storage->isBlocked('1.2.3.4'));
    }

    public function testIsBlockedReturnsTrueAfterBlockIp(): void
    {
        $this->storage->blockIp('1.2.3.4', 3600);

        $this->assertTrue($this->storage->isBlocked('1.2.3.4'));
    }

    public function testIsBlockedReturnsFalseAfterTtlExpired(): void
    {
        // TTL of -1 means the expiry timestamp is in the past.
        $this->storage->blockIp('1.2.3.4', -1);

        $this->assertFalse($this->storage->isBlocked('1.2.3.4'));
    }

    public function testIsBlockedDoesNotAffectOtherIps(): void
    {
        $this->storage->blockIp('1.2.3.4', 3600);

        $this->assertFalse($this->storage->isBlocked('5.6.7.8'));
    }

    public function testExpiredBlockIsRemovedFromStorageOnRead(): void
    {
        $this->storage->blockIp('1.2.3.4', -1);
        $this->storage->isBlocked('1.2.3.4'); // triggers cleanup

        // After cleanup, a fresh block should work normally.
        $this->storage->blockIp('1.2.3.4', 3600);

        $this->assertTrue($this->storage->isBlocked('1.2.3.4'));
    }

    // -------------------------------------------------------------------------
    // addFailure / countFailures
    // -------------------------------------------------------------------------

    public function testCountFailuresReturnsZeroForUnknownIp(): void
    {
        $this->assertSame(0, $this->storage->countFailures('1.2.3.4'));
    }

    public function testAddFailureIncrementsCount(): void
    {
        $this->storage->addFailure('1.2.3.4', 3600);
        $this->storage->addFailure('1.2.3.4', 3600);

        $this->assertSame(2, $this->storage->countFailures('1.2.3.4'));
    }

    public function testCountFailuresIgnoresExpiredEntries(): void
    {
        $this->storage->addFailure('1.2.3.4', 3600); // active
        $this->storage->addFailure('1.2.3.4', -1);   // expired

        $this->assertSame(1, $this->storage->countFailures('1.2.3.4'));
    }

    public function testCountFailuresDoesNotMixDifferentIps(): void
    {
        $this->storage->addFailure('1.2.3.4', 3600);
        $this->storage->addFailure('1.2.3.4', 3600);
        $this->storage->addFailure('5.6.7.8', 3600);

        $this->assertSame(2, $this->storage->countFailures('1.2.3.4'));
        $this->assertSame(1, $this->storage->countFailures('5.6.7.8'));
    }

    // -------------------------------------------------------------------------
    // blockIp
    // -------------------------------------------------------------------------

    public function testBlockIpWithZeroTtlIsNotBlocked(): void
    {
        // time() + 0 == time(), and the check is time() < expiresAt, so 0-TTL expires immediately.
        $this->storage->blockIp('1.2.3.4', 0);

        $this->assertFalse($this->storage->isBlocked('1.2.3.4'));
    }

    // -------------------------------------------------------------------------
    // resetFailures
    // -------------------------------------------------------------------------

    public function testResetFailuresClearsAllFailuresForIp(): void
    {
        $this->storage->addFailure('1.2.3.4', 3600);
        $this->storage->addFailure('1.2.3.4', 3600);
        $this->storage->resetFailures('1.2.3.4');

        $this->assertSame(0, $this->storage->countFailures('1.2.3.4'));
    }

    public function testResetFailuresDoesNotAffectOtherIps(): void
    {
        $this->storage->addFailure('1.2.3.4', 3600);
        $this->storage->addFailure('5.6.7.8', 3600);
        $this->storage->resetFailures('1.2.3.4');

        $this->assertSame(0, $this->storage->countFailures('1.2.3.4'));
        $this->assertSame(1, $this->storage->countFailures('5.6.7.8'));
    }

    public function testResetFailuresOnUnknownIpDoesNotThrow(): void
    {
        $this->storage->resetFailures('9.9.9.9'); // should not throw

        $this->assertSame(0, $this->storage->countFailures('9.9.9.9'));
    }

    // -------------------------------------------------------------------------
    // File / directory handling
    // -------------------------------------------------------------------------

    public function testCreatesFileIfItDoesNotExist(): void
    {
        $this->assertFileDoesNotExist($this->tempFile);

        $this->storage->blockIp('1.2.3.4', 3600);

        $this->assertFileExists($this->tempFile);
    }

    public function testCreatesNestedDirectoryIfItDoesNotExist(): void
    {
        $tempDir = sys_get_temp_dir() . '/fail_sentry_test_' . uniqid();
        $filePath = $tempDir . '/nested/sub/storage.json';

        try {
            $storage = new FileStorage($filePath);
            $storage->blockIp('1.2.3.4', 3600);

            $this->assertFileExists($filePath);
        } finally {
            if (file_exists($filePath)) {
                unlink($filePath);
            }

            foreach (['/nested/sub', '/nested', ''] as $suffix) {
                $dir = $tempDir . $suffix;
                if (is_dir($dir)) {
                    rmdir($dir);
                }
            }
        }
    }

    public function testThrowsRuntimeExceptionWhenFileCannotBeOpened(): void
    {
        $this->expectException(RuntimeException::class);

        // Pointing to a path where the parent is a file, not a directory, makes mkdir fail.
        $filePath = $this->tempFile . '/invalid/path.json';
        // Create the temp file so the path component is a file, not a dir.
        file_put_contents($this->tempFile, '');

        $storage = new FileStorage($filePath);
        $storage->blockIp('1.2.3.4', 3600);
    }

    // -------------------------------------------------------------------------
    // File size and writes
    // -------------------------------------------------------------------------

    public function testExpiredEntriesOfEveryIpAreDroppedAtTheNextWrite(): void
    {
        $this->storage->addFailure('1.1.1.1', -1);
        $this->storage->blockIp('2.2.2.2', -1);
        $this->storage->addFailure('3.3.3.3', 3600);

        $content = (string) file_get_contents($this->tempFile);

        $this->assertStringNotContainsString('1.1.1.1', $content);
        $this->assertStringNotContainsString('2.2.2.2', $content);
        $this->assertStringContainsString('3.3.3.3', $content);
    }

    public function testReadsDoNotRewriteTheFile(): void
    {
        $this->storage->addFailure('1.2.3.4', 3600);
        $before = (string) file_get_contents($this->tempFile);
        file_put_contents($this->tempFile, $before . "\n");

        $this->storage->isBlocked('1.2.3.4');
        $this->storage->countFailures('1.2.3.4');
        $this->storage->resetFailures('5.6.7.8');

        $this->assertSame($before . "\n", file_get_contents($this->tempFile));
    }

    public function testCorruptedFileIsTreatedAsEmpty(): void
    {
        file_put_contents($this->tempFile, '{not json');

        $this->assertFalse($this->storage->isBlocked('1.2.3.4'));
        $this->assertSame(0, $this->storage->countFailures('1.2.3.4'));

        $this->storage->addFailure('1.2.3.4', 3600);
        $this->assertSame(1, $this->storage->countFailures('1.2.3.4'));
    }
}
