import Foundation
@testable import PreludeAuth
import XCTest

/// `/revoke`-side contracts that don't fit `LogoutTests`:
/// proof shape, epoch-after-wipe ordering, and the silent-
/// degrade path on a signing failure.
final class LogoutDPoPTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "logout-dpop-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    override func tearDown() {
        domain = nil; baseURL = nil; clock = nil
        super.tearDown()
    }

    // MARK: - DPoP proof on /revoke

    /// `/revoke` must carry a DPoP proof bound to the session's
    /// keypair, with `nonce` set to the cached value. Pinning
    /// the nonce catches a regression that drops the snapshot
    /// read or signs without the cached value — either of which
    /// would force a `use_dpop_nonce` retry the SDK can't
    /// recover from (the keypair is wiped by then).
    func test_revoke_carriesDPoPProof_withCachedNonce() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate(nonce: "nonce-revoke")
        fixture.http.install(path: "/v1/session/revoke", response: .noContent)

        try await fixture.client.logout()

        let req = try XCTUnwrap(fixture.http.requests(forPath: "/v1/session/revoke").first)
        let proof = try XCTUnwrap(req.value(forHTTPHeaderField: HTTPHeader.dpop))
        let claims = try StepUpFixtures.decodeJWTPayload(proof)
        XCTAssertEqual(claims["nonce"] as? String, "nonce-revoke")
        XCTAssertEqual(claims["htm"] as? String, "POST")
        XCTAssertEqual(
            claims["htu"] as? String,
            "https://\(domain!)/v1/session/revoke"
        )
    }

    /// `/revoke` is signed inline (bypassing the interceptor), so
    /// it must read the persisted clock skew from the snapshot just
    /// like the interceptor does. Without this the proof's `iat`
    /// stays uncorrected and a clock-drifted device gets rejected
    /// — the exact failure mode this PR fixes elsewhere.
    func test_revoke_carriesClockSkewCorrection() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate(nonce: "nonce-revoke")
        let skewSec: TimeInterval = 45
        try fixture.keyStore.setClockSkew(domain: domain, skew: skewSec)
        fixture.http.install(path: "/v1/session/revoke", response: .noContent)

        try await fixture.client.logout()

        let req = try XCTUnwrap(fixture.http.requests(forPath: "/v1/session/revoke").first)
        let proof = try XCTUnwrap(req.value(forHTTPHeaderField: HTTPHeader.dpop))
        let iat = try XCTUnwrap(StepUpFixtures.decodeJWTPayload(proof)["iat"] as? Int)
        XCTAssertEqual(
            TimeInterval(iat),
            Date().addingTimeInterval(skewSec).timeIntervalSince1970,
            accuracy: 3.0,
            "/revoke proof iat must carry the snapshotted skew"
        )
    }

    // MARK: - Epoch order: wipe → bump → /revoke

    /// At the moment `/revoke` is in flight, both the wipe and
    /// the epoch bump must already have landed. Pinning both
    /// catches a regression that reorders bump back to before
    /// the wipe (resurrection window).
    func test_logout_wipesAndBumpsEpoch_beforeFiringRevoke() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate(nonce: "n1")
        fixture.http.install(path: "/v1/session/revoke", response: .noContent)
        fixture.http.installGate(path: "/v1/session/revoke")

        let epochBefore = await fixture.client.impl.sessionEpoch

        let logout = Task { try await fixture.client.logout() }
        try await waitUntil { fixture.http.requestCount(forPath: "/v1/session/revoke") >= 1 }

        try await fixture.assertWiped() // wipe landed pre-/revoke

        let epochDuring = await fixture.client.impl.sessionEpoch
        XCTAssertEqual(
            epochDuring, epochBefore + 1,
            "epoch must be bumped before /revoke fires"
        )

        fixture.http.releaseGate(path: "/v1/session/revoke")
        try await logout.value
    }

    // MARK: - Signing failure → silent degrade

    /// Keychain key invalidated (`errSecAuthFailed` analogue):
    /// the signing call inside doLogout throws. The wipe has
    /// already landed; force callers to handle a thrown error
    /// here would muddy the logout API. Skip `/revoke`, return
    /// cleanly.
    func test_logout_signingFailure_returnsCleanly_noRevokeAttempt() async throws {
        let fixture = try makeFailingSigningFixture()
        try await fixture.prePopulate(nonce: "n1")

        // Will fail loudly if /revoke is hit (no canned response).
        try await fixture.client.logout()

        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/revoke"), 0)
        try await fixture.assertWiped()
    }

    /// Negative side: a network/HTTP failure during `/revoke`
    /// (signing succeeded; wire failed) must still surface so
    /// callers can retry the revocation. Distinguish from
    /// signing-failure silent degrade.
    func test_logout_networkFailureOnRevoke_surfaces() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate(nonce: "n1")
        fixture.http.install(
            path: "/v1/session/revoke",
            response: .json(
                ["code": "internal_server_error", "message": "boom"], statusCode: 500
            )
        )

        do {
            try await fixture.client.logout()
            XCTFail("expected /revoke 500 to surface")
        } catch {}

        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/revoke"), 1)
    }

    // MARK: - Helpers

    private func makeFailingSigningFixture() throws -> Fixture {
        let backend = InMemoryKeychainBackend()
        let inner = SoftwareDPoPKeyStore(backend: backend)
        let failingKeyStore = FailingSigningKeyStore(inner: inner)
        let refreshTokenStore = RefreshTokenStore(keychain: backend)
        let accessTokenCache = AccessTokenCache(clock: clock, keychain: backend)
        let http = StubHTTPSession()

        let client = try PreludeAuthClient(
            baseURL: baseURL, hostOverride: nil, signalsDispatcher: nil,
            timeout: 1, httpSession: http, clock: clock,
            keyStore: failingKeyStore,
            refreshTokenStore: refreshTokenStore,
            accessTokenCache: accessTokenCache
        )
        return Fixture(
            client: client, http: http, keyStore: inner,
            refreshTokenStore: refreshTokenStore, accessTokenCache: accessTokenCache,
            domain: domain, clock: clock
        )
    }

    private func waitUntil(
        timeout: TimeInterval = 2,
        file: StaticString = #filePath,
        line: UInt = #line,
        _ condition: @escaping () -> Bool
    ) async throws {
        let start = Date()
        while Date().timeIntervalSince(start) < timeout {
            if condition() {
                return
            }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("timed out", file: file, line: line)
    }
}

// MARK: - Test doubles

/// Wraps a real `DPoPKeyStore` but returns a key whose
/// `signES256` throws — simulating a Secure Enclave key
/// invalidated by a biometric reset (`errSecAuthFailed`).
private struct FailingSigningKeyStore: DPoPKeyStore {
    let inner: any DPoPKeyStore

    var backend: KeychainBackend {
        inner.backend
    }

    var nonceStore: DPoPNonceStore {
        inner.nonceStore
    }

    var clockSkewStore: DPoPClockSkewStore {
        inner.clockSkewStore
    }

    func create(domain: String) throws -> DPoPKey {
        try FailingSigningKey(real: inner.create(domain: domain))
    }

    func get(domain: String) throws -> DPoPKey? {
        try inner.get(domain: domain).map { FailingSigningKey(real: $0) }
    }

    func getOrCreate(domain: String) throws -> DPoPKey {
        try FailingSigningKey(real: inner.getOrCreate(domain: domain))
    }

    func delete(domain: String) throws {
        try inner.delete(domain: domain)
    }

    func getNonce(domain: String) throws -> String? {
        try inner.getNonce(domain: domain)
    }

    func setNonce(domain: String, nonce: String) throws {
        try inner.setNonce(domain: domain, nonce: nonce)
    }

    func deleteNonce(domain: String) throws {
        try inner.deleteNonce(domain: domain)
    }
}

private struct FailingSigningKey: DPoPKey {
    let real: DPoPKey

    func exportPublicJWK() throws -> [String: String] {
        try real.exportPublicJWK()
    }

    func signES256(_: Data) throws -> Data {
        throw DPoPProofError.signingFailed(underlying: nil)
    }
}
