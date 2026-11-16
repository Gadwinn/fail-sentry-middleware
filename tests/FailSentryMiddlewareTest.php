<?php

declare(strict_types=1);

namespace G\FailSentryMiddleware\Tests;

use G\FailSentryMiddleware\FailSentryMiddleware;
use G\FailSentryMiddleware\Storage\StorageInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use RuntimeException;

class FailSentryMiddlewareTest extends TestCase
{
    /** @var StorageInterface&MockObject */
    private StorageInterface $storage;

    /** @var ResponseFactoryInterface&MockObject */
    private ResponseFactoryInterface $responseFactory;

    private ResponseInterface $blockedResponse;

    /** @var ServerRequestInterface&MockObject */
    private ServerRequestInterface $request;

    /** @var RequestHandlerInterface&MockObject */
    private RequestHandlerInterface $handler;

    protected function setUp(): void
    {
        $this->storage = $this->createMock(StorageInterface::class);
        $blockedResponse = $this->createStub(ResponseInterface::class);
        $blockedResponse->method('withHeader')->willReturnSelf();
        $this->blockedResponse = $blockedResponse;

        $this->responseFactory = $this->createStub(ResponseFactoryInterface::class);
        $this->responseFactory->method('createResponse')->willReturn($this->blockedResponse);

        $this->request = $this->createStub(ServerRequestInterface::class);
        $this->request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '1.2.3.4']);
        $this->request->method('getHeaderLine')->willReturn('');

        $this->handler = $this->createMock(RequestHandlerInterface::class);
    }

    public function testWhitelistedIpSkipsAllChecksAndCallsHandler(): void
    {
        $handlerResponse = $this->createStub(ResponseInterface::class);
        $this->handler->expects($this->once())->method('handle')->willReturn($handlerResponse);
        $this->storage->expects($this->never())->method('isBlocked');

        $middleware = new FailSentryMiddleware(
            storage: $this->storage,
            responseFactory: $this->responseFactory,
            whitelistedIps: ['1.2.3.4'],
        );

        $result = $middleware->process($this->request, $this->handler);

        $this->assertSame($handlerResponse, $result);
    }

    public function testWhitelistedCidrRangeSkipsAllChecks(): void
    {
        $handlerResponse = $this->createStub(ResponseInterface::class);
        $this->handler->expects($this->once())->method('handle')->willReturn($handlerResponse);
        $this->storage->expects($this->never())->method('isBlocked');

        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.168.1.50']);
        $request->method('getHeaderLine')->willReturn('');

        $middleware = new FailSentryMiddleware(
            storage: $this->storage,
            responseFactory: $this->responseFactory,
            whitelistedIps: ['192.168.1.0/24'],
        );

        $result = $middleware->process($request, $this->handler);

        $this->assertSame($handlerResponse, $result);
    }

    public function testBlockedIpReturns429WithoutCallingHandler(): void
    {
        $this->storage->expects($this->atLeastOnce())->method('isBlocked')->with('1.2.3.4')->willReturn(true);
        $this->handler->expects($this->never())->method('handle');

        $middleware = new FailSentryMiddleware($this->storage, $this->responseFactory);

        $result = $middleware->process($this->request, $this->handler);

        $this->assertSame($this->blockedResponse, $result);
    }

    public function testSuccessfulResponseResetsFailuresAndReturnsResponse(): void
    {
        $successResponse = $this->createStub(ResponseInterface::class);
        $successResponse->method('getStatusCode')->willReturn(200);

        $this->storage->expects($this->atLeastOnce())->method('isBlocked')->willReturn(false);
        $this->handler->expects($this->atLeastOnce())->method('handle')->willReturn($successResponse);
        $this->storage->expects($this->once())->method('resetFailures')->with('1.2.3.4');
        $this->storage->expects($this->never())->method('addFailure');

        $middleware = new FailSentryMiddleware($this->storage, $this->responseFactory, resetOnSuccess: true);

        $result = $middleware->process($this->request, $this->handler);

        $this->assertSame($successResponse, $result);
    }

    public function testFailedResponseIncrementsCounterAndReturnsOriginalResponse(): void
    {
        $failResponse = $this->createStub(ResponseInterface::class);
        $failResponse->method('getStatusCode')->willReturn(401);

        $this->storage->expects($this->atLeastOnce())->method('isBlocked')->willReturn(false);
        $this->handler->expects($this->atLeastOnce())->method('handle')->willReturn($failResponse);
        $this->storage->expects($this->once())->method('addFailure')->with('1.2.3.4', 3600);
        $this->storage->expects($this->atLeastOnce())->method('countFailures')->willReturn(1);
        $this->storage->expects($this->never())->method('blockIp');

        $middleware = new FailSentryMiddleware($this->storage, $this->responseFactory);

        $result = $middleware->process($this->request, $this->handler);

        $this->assertSame($failResponse, $result);
    }

    public function testReachingMaxAttemptsBlocksIpAndReturns429(): void
    {
        $failResponse = $this->createStub(ResponseInterface::class);
        $failResponse->method('getStatusCode')->willReturn(401);

        $this->storage->expects($this->atLeastOnce())->method('isBlocked')->willReturn(false);
        $this->handler->expects($this->atLeastOnce())->method('handle')->willReturn($failResponse);
        $this->storage->expects($this->atLeastOnce())->method('countFailures')->willReturn(5);
        $this->storage->expects($this->once())->method('blockIp')->with('1.2.3.4', 3600);

        $middleware = new FailSentryMiddleware($this->storage, $this->responseFactory);

        $result = $middleware->process($this->request, $this->handler);

        $this->assertSame($this->blockedResponse, $result);
    }

    public function testCustomMaxAttemptsIsRespected(): void
    {
        $failResponse = $this->createStub(ResponseInterface::class);
        $failResponse->method('getStatusCode')->willReturn(401);

        $this->storage->expects($this->atLeastOnce())->method('isBlocked')->willReturn(false);
        $this->handler->expects($this->atLeastOnce())->method('handle')->willReturn($failResponse);
        $this->storage->expects($this->atLeastOnce())->method('countFailures')->willReturn(3);
        $this->storage->expects($this->once())->method('blockIp');

        $middleware = new FailSentryMiddleware(
            storage: $this->storage,
            responseFactory: $this->responseFactory,
            maxAttempts: 3,
        );

        $middleware->process($this->request, $this->handler);
    }

    public function testCustomFailureDetectorOverridesDefaultCodes(): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200); // normally a success

        $this->storage->expects($this->atLeastOnce())->method('isBlocked')->willReturn(false);
        $this->handler->expects($this->atLeastOnce())->method('handle')->willReturn($response);
        $this->storage->expects($this->once())->method('addFailure');
        $this->storage->expects($this->atLeastOnce())->method('countFailures')->willReturn(1);

        // Custom detector: treat 200 as a failure
        $detector = static fn (ResponseInterface $r): bool => $r->getStatusCode() === 200;

        $middleware = new FailSentryMiddleware(
            storage: $this->storage,
            responseFactory: $this->responseFactory,
            failureDetector: $detector,
        );

        $middleware->process($this->request, $this->handler);
    }

    public function testCustomBlockTtlIsPassedToStorage(): void
    {
        $failResponse = $this->createStub(ResponseInterface::class);
        $failResponse->method('getStatusCode')->willReturn(403);

        $this->storage->expects($this->atLeastOnce())->method('isBlocked')->willReturn(false);
        $this->handler->expects($this->atLeastOnce())->method('handle')->willReturn($failResponse);
        $this->storage->expects($this->atLeastOnce())->method('countFailures')->willReturn(5);
        $this->storage->expects($this->once())->method('blockIp')->with('1.2.3.4', 7200);

        $middleware = new FailSentryMiddleware(
            storage: $this->storage,
            responseFactory: $this->responseFactory,
            blockTtl: 7200,
        );

        $middleware->process($this->request, $this->handler);
    }

    public function testCustomFailureTtlIsPassedToStorage(): void
    {
        $failResponse = $this->createStub(ResponseInterface::class);
        $failResponse->method('getStatusCode')->willReturn(403);

        $this->storage->expects($this->atLeastOnce())->method('isBlocked')->willReturn(false);
        $this->handler->expects($this->atLeastOnce())->method('handle')->willReturn($failResponse);
        $this->storage->expects($this->once())->method('addFailure')->with('1.2.3.4', 600);
        $this->storage->expects($this->atLeastOnce())->method('countFailures')->willReturn(1);

        $middleware = new FailSentryMiddleware(
            storage: $this->storage,
            responseFactory: $this->responseFactory,
            failureTtl: 600,
        );

        $middleware->process($this->request, $this->handler);
    }

    public function testIpResolvedFromRemoteAddrWhenNoTrustedProxies(): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);

        $this->storage->expects($this->atLeastOnce())->method('isBlocked')->with('1.2.3.4')->willReturn(false);
        $this->handler->expects($this->atLeastOnce())->method('handle')->willReturn($response);
        $this->storage->expects($this->once())->method('resetFailures')->with('1.2.3.4');

        $middleware = new FailSentryMiddleware($this->storage, $this->responseFactory, resetOnSuccess: true);

        $middleware->process($this->request, $this->handler);
    }

    public function testIpResolvedFromXForwardedForBehindTrustedProxy(): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);

        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '10.0.0.1']);
        $request->method('getHeaderLine')->willReturnMap([
            ['X-Forwarded-For', '5.6.7.8, 10.0.0.1'],
            ['X-Real-IP', ''],
        ]);

        $this->storage->expects($this->atLeastOnce())->method('isBlocked')->with('5.6.7.8')->willReturn(false);
        $this->handler->expects($this->atLeastOnce())->method('handle')->willReturn($response);
        $this->storage->expects($this->once())->method('resetFailures')->with('5.6.7.8');

        $middleware = new FailSentryMiddleware(
            storage: $this->storage,
            responseFactory: $this->responseFactory,
            trustedProxies: ['10.0.0.1'],
            resetOnSuccess: true,
        );

        $middleware->process($request, $this->handler);
    }

    public function testIpResolvedFromXRealIpWhenXForwardedForIsEmpty(): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);

        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '10.0.0.1']);
        $request->method('getHeaderLine')->willReturnMap([
            ['X-Forwarded-For', ''],
            ['X-Real-IP', '9.9.9.9'],
        ]);

        $this->storage->expects($this->atLeastOnce())->method('isBlocked')->with('9.9.9.9')->willReturn(false);
        $this->handler->expects($this->atLeastOnce())->method('handle')->willReturn($response);
        $this->storage->expects($this->once())->method('resetFailures')->with('9.9.9.9');

        $middleware = new FailSentryMiddleware(
            storage: $this->storage,
            responseFactory: $this->responseFactory,
            trustedProxies: ['10.0.0.1'],
            resetOnSuccess: true,
        );

        $middleware->process($request, $this->handler);
    }

    public function testRemoteAddrUsedWhenProxyIsNotTrusted(): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);

        // REMOTE_ADDR is NOT in trustedProxies, so X-Forwarded-For must be ignored
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '8.8.8.8']);
        $request->method('getHeaderLine')->willReturnMap([
            ['X-Forwarded-For', '1.1.1.1'],
            ['X-Real-IP', ''],
        ]);

        $this->storage->expects($this->atLeastOnce())->method('isBlocked')->with('8.8.8.8')->willReturn(false);
        $this->handler->expects($this->atLeastOnce())->method('handle')->willReturn($response);
        $this->storage->expects($this->once())->method('resetFailures')->with('8.8.8.8');

        $middleware = new FailSentryMiddleware(
            storage: $this->storage,
            responseFactory: $this->responseFactory,
            trustedProxies: ['10.0.0.1'],
            resetOnSuccess: true,
        );

        $middleware->process($request, $this->handler);
    }

    public function testTrustedProxyCidrRangeIsSupported(): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);

        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '10.0.0.50']);
        $request->method('getHeaderLine')->willReturnMap([
            ['X-Forwarded-For', '203.0.113.5'],
            ['X-Real-IP', ''],
        ]);

        $this->storage->expects($this->atLeastOnce())->method('isBlocked')->with('203.0.113.5')->willReturn(false);
        $this->handler->expects($this->atLeastOnce())->method('handle')->willReturn($response);
        $this->storage->expects($this->once())->method('resetFailures')->with('203.0.113.5');

        $middleware = new FailSentryMiddleware(
            storage: $this->storage,
            responseFactory: $this->responseFactory,
            trustedProxies: ['10.0.0.0/8'],
            resetOnSuccess: true,
        );

        $middleware->process($request, $this->handler);
    }

    public function testInvalidRemoteAddrFailsOpenByDefault(): void
    {
        $response = $this->createStub(ResponseInterface::class);

        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => 'not-an-ip']);
        $request->method('getHeaderLine')->willReturn('');

        $this->handler->expects($this->once())->method('handle')->willReturn($response);
        $this->storage->expects($this->never())->method('isBlocked');

        $middleware = new FailSentryMiddleware($this->storage, $this->responseFactory);

        $result = $middleware->process($request, $this->handler);

        $this->assertSame($response, $result);
    }

    public function testInvalidRemoteAddrFailsClosedWhenConfigured(): void
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => 'not-an-ip']);
        $request->method('getHeaderLine')->willReturn('');

        $this->handler->expects($this->never())->method('handle');
        $this->storage->expects($this->never())->method('isBlocked');

        $middleware = new FailSentryMiddleware(
            storage: $this->storage,
            responseFactory: $this->responseFactory,
            failOpenOnStorageError: false,
        );

        $result = $middleware->process($request, $this->handler);

        $this->assertSame($this->blockedResponse, $result);
    }

    public function testStorageFailureFailsOpenByDefault(): void
    {
        $response = $this->createStub(ResponseInterface::class);

        $this->storage->expects($this->once())
            ->method('isBlocked')
            ->willThrowException(new RuntimeException('storage down'));
        $this->handler->expects($this->once())->method('handle')->willReturn($response);

        $middleware = new FailSentryMiddleware($this->storage, $this->responseFactory);

        $result = $middleware->process($this->request, $this->handler);

        $this->assertSame($response, $result);
    }

    public function testStorageFailureCanFailClosedWhenConfigured(): void
    {
        $this->storage->expects($this->once())
            ->method('isBlocked')
            ->willThrowException(new RuntimeException('storage down'));
        $this->handler->expects($this->never())->method('handle');

        $middleware = new FailSentryMiddleware(
            storage: $this->storage,
            responseFactory: $this->responseFactory,
            failOpenOnStorageError: false,
        );

        $result = $middleware->process($this->request, $this->handler);

        $this->assertSame($this->blockedResponse, $result);
    }

    public function testBlockedResponseContainsRetryAfterHeader(): void
    {
        $blockedResponse = $this->createMock(ResponseInterface::class);
        $blockedResponse->expects($this->exactly(2))->method('withHeader')->willReturnSelf();

        $responseFactory = $this->createStub(ResponseFactoryInterface::class);
        $responseFactory->method('createResponse')->willReturn($blockedResponse);

        $this->storage->expects($this->once())->method('isBlocked')->willReturn(true);
        $this->handler->expects($this->never())->method('handle');

        $middleware = new FailSentryMiddleware(
            storage: $this->storage,
            responseFactory: $responseFactory,
            blockTtl: 120,
        );

        $middleware->process($this->request, $this->handler);
    }

    // -------------------------------------------------------------------------
    // IP notation
    // -------------------------------------------------------------------------

    public function testIpv6IsStoredInCanonicalForm(): void
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '2001:0DB8:0:0:0:0:0:0001']);
        $request->method('getHeaderLine')->willReturn('');

        $this->storage->expects($this->once())->method('isBlocked')->with('2001:db8::1')->willReturn(true);
        $this->handler->expects($this->never())->method('handle');

        $middleware = new FailSentryMiddleware(storage: $this->storage, responseFactory: $this->responseFactory);

        $this->assertSame($this->blockedResponse, $middleware->process($request, $this->handler));
    }

    public function testWhitelistMatchesAnyNotationOfTheSameIpv6(): void
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '::1']);
        $request->method('getHeaderLine')->willReturn('');

        $handlerResponse = $this->createStub(ResponseInterface::class);
        $this->handler->expects($this->once())->method('handle')->willReturn($handlerResponse);
        $this->storage->expects($this->never())->method('isBlocked');

        $middleware = new FailSentryMiddleware(
            storage: $this->storage,
            responseFactory: $this->responseFactory,
            whitelistedIps: ['0:0:0:0:0:0:0:1'],
        );

        $this->assertSame($handlerResponse, $middleware->process($request, $this->handler));
    }

    public function testIpv6CidrRangeIsSupported(): void
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '2001:db8:abcd::42']);
        $request->method('getHeaderLine')->willReturn('');

        $handlerResponse = $this->createStub(ResponseInterface::class);
        $this->handler->expects($this->once())->method('handle')->willReturn($handlerResponse);
        $this->storage->expects($this->never())->method('isBlocked');

        $middleware = new FailSentryMiddleware(
            storage: $this->storage,
            responseFactory: $this->responseFactory,
            whitelistedIps: ['2001:db8::/32'],
        );

        $this->assertSame($handlerResponse, $middleware->process($request, $this->handler));
    }

    public function testMalformedCidrPrefixNeverMatches(): void
    {
        $this->storage->expects($this->exactly(3))->method('isBlocked')->willReturn(true);
        $this->handler->expects($this->never())->method('handle');

        foreach (['1.2.3.0/2e1', '1.2.3.0/24.0', '1.2.3.0/ 24'] as $range) {
            $middleware = new FailSentryMiddleware(
                storage: $this->storage,
                responseFactory: $this->responseFactory,
                whitelistedIps: [$range],
            );

            $this->assertSame($this->blockedResponse, $middleware->process($this->request, $this->handler));
        }
    }

    // -------------------------------------------------------------------------
    // Defaults
    // -------------------------------------------------------------------------

    public function testSuccessfulResponseDoesNotResetFailuresByDefault(): void
    {
        $successResponse = $this->createStub(ResponseInterface::class);
        $successResponse->method('getStatusCode')->willReturn(200);

        $this->storage->expects($this->once())->method('isBlocked')->willReturn(false);
        $this->handler->expects($this->once())->method('handle')->willReturn($successResponse);
        $this->storage->expects($this->never())->method('resetFailures');
        $this->storage->expects($this->never())->method('addFailure');

        $middleware = new FailSentryMiddleware($this->storage, $this->responseFactory);

        $this->assertSame($successResponse, $middleware->process($this->request, $this->handler));
    }

    public function testNotFoundIsNotAFailureByDefault(): void
    {
        $notFound = $this->createStub(ResponseInterface::class);
        $notFound->method('getStatusCode')->willReturn(404);

        $this->storage->expects($this->once())->method('isBlocked')->willReturn(false);
        $this->handler->expects($this->once())->method('handle')->willReturn($notFound);
        $this->storage->expects($this->never())->method('addFailure');

        $middleware = new FailSentryMiddleware($this->storage, $this->responseFactory);

        $this->assertSame($notFound, $middleware->process($this->request, $this->handler));
    }

    // --- ipAttribute

    /**
     * @param array<string, mixed> $attributes
     */
    private function requestWithAttributes(string $remoteAddr, array $attributes): ServerRequestInterface
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => $remoteAddr]);
        $request->method('getHeaderLine')->willReturn('');
        $request->method('getAttribute')->willReturnCallback(
            static fn (string $name, mixed $default = null): mixed => $attributes[$name] ?? $default
        );

        return $request;
    }

    public function testIpAttributeReplacesTheInternalResolution(): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);

        $this->storage->expects($this->once())->method('isBlocked')->with('2001:db8::1')->willReturn(false);
        $this->handler->expects($this->atLeastOnce())->method('handle')->willReturn($response);

        $middleware = new FailSentryMiddleware(
            storage: $this->storage,
            responseFactory: $this->responseFactory,
            ipAttribute: 'client_ip',
        );

        $middleware->process($this->requestWithAttributes('10.0.0.1', ['client_ip' => '2001:DB8:0::1']), $this->handler);
    }

    public function testIpAttributeIsIgnoredWhenMissingOrInvalid(): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);

        $this->storage->expects($this->exactly(3))->method('isBlocked')->with('10.0.0.1')->willReturn(false);
        $this->handler->expects($this->atLeastOnce())->method('handle')->willReturn($response);

        $middleware = new FailSentryMiddleware(
            storage: $this->storage,
            responseFactory: $this->responseFactory,
            ipAttribute: 'client_ip',
        );

        foreach ([[], ['client_ip' => 'not-an-ip'], ['client_ip' => 42]] as $attributes) {
            $middleware->process($this->requestWithAttributes('10.0.0.1', $attributes), $this->handler);
        }
    }

    public function testIpAttributeIsNotReadWhenNotConfigured(): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);

        $this->storage->expects($this->once())->method('isBlocked')->with('10.0.0.1')->willReturn(false);
        $this->handler->expects($this->atLeastOnce())->method('handle')->willReturn($response);

        $middleware = new FailSentryMiddleware(storage: $this->storage, responseFactory: $this->responseFactory);

        $middleware->process($this->requestWithAttributes('10.0.0.1', ['client_ip' => '1.2.3.4']), $this->handler);
    }
}
