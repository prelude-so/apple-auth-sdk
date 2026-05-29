import Foundation
@testable import PreludeAuth
import XCTest

/// `invalid_dpop_proof` + clock-skew retry path:
///   - retry once when `|skew| >= 1.0s`,
///   - persist the skew so subsequent requests are pre-corrected,
///   - leave sub-threshold or unparseable-`Date` responses alone
///     so an unrelated `invalid_dpop_proof` surfaces as the error
///     the caller expects.
final class DPoPClockSkewTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "dpop-skew-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    override func tearDown() {
        domain = nil; baseURL = nil; clock = nil
        super.tearDown()
    }

    private let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.s"

    // MARK: - (a) Skew above threshold → retry once and persist

    func test_invalidDPoPProof_aboveThreshold_persistsSkewAndRetries() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate(accessTokenExpired: true)

        let serverAhead: TimeInterval = 30
        let serverDate = httpDate(Date().addingTimeInterval(serverAhead))
        fixture.http.installSequence(
            path: "/v1/session/refresh",
            responses: [
                StubHTTPSession.CannedResponse(
                    statusCode: 400,
                    body: error("invalid_dpop_proof"),
                    headers: ["Content-Type": "application/json", HTTPHeader.date: serverDate]
                ),
                .json(
                    [
                        "access_token": jwt,
                        "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                    ],
                    headers: [HTTPHeader.refreshToken: "r2"]
                ),
            ]
        )

        _ = try await fixture.client.refresh()

        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/refresh"), 2)
        let persisted = try XCTUnwrap(try fixture.keyStore.getClockSkew(domain: domain))
        XCTAssertEqual(persisted, serverAhead, accuracy: 2.0)

        // Retry proof's iat must lie in the server's frame.
        let reqs = fixture.http.requests(forPath: "/v1/session/refresh")
        let retryIat = try iat(in: XCTUnwrap(reqs[1].value(forHTTPHeaderField: HTTPHeader.dpop)))
        XCTAssertEqual(
            TimeInterval(retryIat),
            Date().addingTimeInterval(serverAhead).timeIntervalSince1970,
            accuracy: 3.0,
            "retry iat must carry the corrected skew"
        )
    }

    // MARK: - (b) Sub-threshold skew → no retry, error propagates

    /// The server's `Date:` resolution is whole seconds, so a header
    /// at current wall-clock yields a computed skew in `[-1, 0]s` —
    /// strictly below the 1.0s retry threshold.
    func test_invalidDPoPProof_subThresholdSkew_doesNotRetry() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate(accessTokenExpired: true)

        fixture.http.install(
            path: "/v1/session/refresh",
            response: StubHTTPSession.CannedResponse(
                statusCode: 400,
                body: error("invalid_dpop_proof"),
                headers: ["Content-Type": "application/json", HTTPHeader.date: httpDate(Date())]
            )
        )

        do {
            _ = try await fixture.client.refresh()
            XCTFail("expected error to propagate")
        } catch {}

        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/refresh"), 1)
        XCTAssertNil(try fixture.keyStore.getClockSkew(domain: domain))
    }

    // MARK: - (c) Missing Date header → no retry, error propagates

    func test_invalidDPoPProof_noDateHeader_doesNotRetry() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate(accessTokenExpired: true)

        fixture.http.install(
            path: "/v1/session/refresh",
            response: StubHTTPSession.CannedResponse(
                statusCode: 400,
                body: error("invalid_dpop_proof"),
                headers: ["Content-Type": "application/json"]
            )
        )

        do {
            _ = try await fixture.client.refresh()
            XCTFail("expected error to propagate")
        } catch {}

        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/refresh"), 1)
        XCTAssertNil(try fixture.keyStore.getClockSkew(domain: domain))
    }

    // MARK: - (d) Persisted skew is reused on the next request

    func test_persistedSkew_isAppliedOnSubsequentRequest() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate(accessTokenExpired: true)

        let persistedSkew: TimeInterval = 45
        try fixture.keyStore.setClockSkew(domain: domain, skew: persistedSkew)

        fixture.http.install(
            path: "/v1/session/refresh",
            response: .json(
                [
                    "access_token": jwt,
                    "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                ],
                headers: [HTTPHeader.refreshToken: "r2"]
            )
        )

        _ = try await fixture.client.refresh()

        let req = try XCTUnwrap(fixture.http.requests(forPath: "/v1/session/refresh").first)
        let proofIat = try iat(in: XCTUnwrap(req.value(forHTTPHeaderField: HTTPHeader.dpop)))
        XCTAssertEqual(
            TimeInterval(proofIat),
            Date().addingTimeInterval(persistedSkew).timeIntervalSince1970,
            accuracy: 3.0,
            "first proof after a cached skew must already be corrected"
        )
    }

    // MARK: - (f) Stale persisted skew + sub-threshold response

    /// After a device-clock re-sync the next request still signs
    /// with the previously persisted (now-stale) skew, so the
    /// server rejects with `invalid_dpop_proof` carrying a fresh
    /// `Date:` header that yields a ~0 s computed skew. Without
    /// clearing, the stale correction would replay on every
    /// subsequent request and never self-heal.
    func test_invalidDPoPProof_subThresholdSkew_clearsStalePersistedSkew() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate(accessTokenExpired: true)
        try fixture.keyStore.setClockSkew(domain: domain, skew: 30) // stale, pre-resync

        fixture.http.install(
            path: "/v1/session/refresh",
            response: StubHTTPSession.CannedResponse(
                statusCode: 400,
                body: error("invalid_dpop_proof"),
                headers: ["Content-Type": "application/json", HTTPHeader.date: httpDate(Date())]
            )
        )

        do {
            _ = try await fixture.client.refresh()
            XCTFail("expected error to propagate")
        } catch {}

        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/refresh"), 1)
        XCTAssertNil(
            try fixture.keyStore.getClockSkew(domain: domain),
            "stale skew must be cleared so the next request self-heals"
        )
    }

    // MARK: - (e) Rotated nonce on the error response

    /// Per RFC 9449, the server SHOULD echo `DPoP-Nonce` on every
    /// response. When `invalid_dpop_proof` arrives with a rotated
    /// nonce, the skew retry must persist and use it; otherwise
    /// the retry fires with a stale value and itself fails
    /// `use_dpop_nonce`, with no second retry available.
    func test_invalidDPoPProof_rotatedNonce_isHarvestedAndUsedOnRetry() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate(nonce: "stale-nonce", accessTokenExpired: true)

        let rotatedNonce = "rotated-nonce"
        let serverDate = httpDate(Date().addingTimeInterval(30))
        fixture.http.installSequence(
            path: "/v1/session/refresh",
            responses: [
                StubHTTPSession.CannedResponse(
                    statusCode: 400,
                    body: error("invalid_dpop_proof"),
                    headers: [
                        "Content-Type": "application/json",
                        HTTPHeader.date: serverDate,
                        HTTPHeader.dpopNonce: rotatedNonce,
                    ]
                ),
                .json(
                    [
                        "access_token": jwt,
                        "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                    ],
                    headers: [HTTPHeader.refreshToken: "r2"]
                ),
            ]
        )

        _ = try await fixture.client.refresh()

        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/refresh"), 2)
        XCTAssertEqual(try fixture.keyStore.getNonce(domain: domain), rotatedNonce)

        let reqs = fixture.http.requests(forPath: "/v1/session/refresh")
        let retryProof = try XCTUnwrap(reqs[1].value(forHTTPHeaderField: HTTPHeader.dpop))
        let claims = try StepUpFixtures.decodeJWTPayload(retryProof)
        XCTAssertEqual(
            claims["nonce"] as? String,
            rotatedNonce,
            "retry proof must carry the rotated nonce, not the stale one"
        )
    }

    // MARK: - Oversized error body

    /// A multi-megabyte 4xx body — say, an HTML error page from a
    /// misbehaving proxy — must not be decoded as an API error
    /// just because it happens to mention `invalid_dpop_proof`.
    /// The body-size cap short-circuits the decode and the
    /// response propagates unmodified.
    func test_oversizedErrorBody_skipsDecode_andDoesNotRetry() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate(accessTokenExpired: true)

        let payload =
            #"{"code":"invalid_dpop_proof","filler":""# +
            String(repeating: "a", count: 8 * 1024) + #""}"#
        fixture.http.install(
            path: "/v1/session/refresh",
            response: StubHTTPSession.CannedResponse(
                statusCode: 400,
                body: Data(payload.utf8),
                headers: [
                    "Content-Type": "application/json",
                    HTTPHeader.date: httpDate(Date().addingTimeInterval(30)),
                ]
            )
        )

        do {
            _ = try await fixture.client.refresh()
            XCTFail("expected error to propagate")
        } catch {}

        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/refresh"), 1)
        XCTAssertNil(try fixture.keyStore.getClockSkew(domain: domain))
    }

    // MARK: - Logout cascade

    /// Persisted skew must be wiped alongside the keypair and
    /// nonce on logout. Without this, a stale correction from a
    /// previous session would leak into the next login's first
    /// proof.
    func test_logout_wipesPersistedClockSkew() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()
        try fixture.keyStore.setClockSkew(domain: domain, skew: 30)
        fixture.http.install(path: "/v1/session/revoke", response: .noContent)

        try await fixture.client.logout()

        try await fixture.assertWiped()
    }

    // MARK: - Helpers

    private func error(_ code: String) -> Data {
        // Static shape — no JSONSerialization needed, which keeps
        // the call sites free of `try` (and `hoistTry` happy).
        Data(#"{"code":"\#(code)","message":"\#(code)"}"#.utf8)
    }

    private func iat(in proof: String) throws -> Int {
        try XCTUnwrap(StepUpFixtures.decodeJWTPayload(proof)["iat"] as? Int)
    }

    private func httpDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
        return formatter.string(from: date)
    }
}
