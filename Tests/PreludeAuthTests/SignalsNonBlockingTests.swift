import Foundation
@testable import PreludeAuth
import XCTest

/// Anti-fraud signals are best-effort: a failing
/// ``PreludeSignalsDispatcher`` must not break login. The auth
/// call proceeds, and the wire body omits `dispatch_id`.
final class SignalsNonBlockingTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "signals-nonblocking-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    override func tearDown() {
        domain = nil; baseURL = nil; clock = nil
        super.tearDown()
    }

    private struct DispatcherFailure: Error {}

    /// Stub dispatcher that always throws — simulates a network
    /// failure, timeout, or anti-fraud backend 5xx.
    private struct ThrowingDispatcher: PreludeSignalsDispatcher {
        func dispatch() async throws -> String? {
            throw DispatcherFailure()
        }
    }

    /// Throws `CancellationError` — simulates a parent task that
    /// was cancelled while the dispatcher was in flight.
    private struct CancellingDispatcher: PreludeSignalsDispatcher {
        func dispatch() async throws -> String? {
            throw CancellationError()
        }
    }

    func test_startOTPLogin_proceedsWithoutDispatchID_whenDispatcherThrows() async throws {
        let fixture = try makeFixture(signalsDispatcher: ThrowingDispatcher())
        fixture.http.install(path: "/v1/session/otp", response: .noContent)

        try await fixture.client.startOTPLogin(
            StartOTPLoginOptions(
                identifier: PreludeIdentifier(type: .emailAddress, value: "alice@example.com")
            )
        )

        let req = try XCTUnwrap(fixture.http.requests(forPath: "/v1/session/otp").first)
        let raw = try XCTUnwrap(req.httpBody)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: raw) as? [String: Any])
        XCTAssertNil(
            json["dispatch_id"],
            "signals failures must not surface a dispatch_id on the request body"
        )
    }

    func test_startOTPLogin_propagatesCancellation_andSkipsHTTP() async throws {
        let fixture = try makeFixture(signalsDispatcher: CancellingDispatcher())
        fixture.http.install(path: "/v1/session/otp", response: .noContent)

        do {
            try await fixture.client.startOTPLogin(
                StartOTPLoginOptions(
                    identifier: PreludeIdentifier(type: .emailAddress, value: "alice@example.com")
                )
            )
            XCTFail("expected CancellationError to propagate")
        } catch is CancellationError {
            // expected — structured concurrency must not be swallowed
        }

        // The HTTP layer must never have been reached.
        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/otp"), 0)
    }

    // MARK: - Helpers

    private func makeFixture(
        signalsDispatcher: PreludeSignalsDispatcher
    ) throws -> Fixture {
        let backend = InMemoryKeychainBackend()
        let keyStore = SoftwareDPoPKeyStore(backend: backend)
        let refreshTokenStore = RefreshTokenStore(keychain: backend)
        let accessTokenCache = AccessTokenCache(clock: clock, keychain: backend)
        let http = StubHTTPSession()

        let client = try PreludeAuthClient(
            baseURL: baseURL,
            hostOverride: nil,
            signalsDispatcher: signalsDispatcher,
            timeout: 1,
            httpSession: http,
            clock: clock,
            keyStore: keyStore,
            refreshTokenStore: refreshTokenStore,
            accessTokenCache: accessTokenCache
        )

        return Fixture(
            client: client,
            http: http,
            keyStore: keyStore,
            refreshTokenStore: refreshTokenStore,
            accessTokenCache: accessTokenCache,
            domain: domain,
            clock: clock
        )
    }
}
