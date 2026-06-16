import Foundation
@testable import PreludeAuth
import XCTest

/// Header-level pins for the OTP login flow that don't belong in
/// the DPoP-policy file:
///
///   - no `Authorization: Bearer …` on `/otp`, `/otp/check`, or
///     `/login/finalize` — none of them are protected calls, and
///     a stray Bearer would either be ignored or (worse, behind a
///     strict proxy) rejected before the server could mint the
///     session.
///   - the `DPoP-Nonce` returned by `/login/finalize` is harvested
///     into the per-domain keystore so the next DPoP-signed call
///     (refresh, step-up, …) reuses it without an extra
///     `use_dpop_nonce` round-trip (RFC 9449 §8).
final class OTPLoginHeadersTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "otp-headers-test-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    override func tearDown() {
        domain = nil
        baseURL = nil
        clock = nil
        super.tearDown()
    }

    /// Well-formed unsigned JWT — `JWT.decode` reads payload only.
    private let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.sig"

    // MARK: - No Authorization on the OTP hops

    /// `/otp` and `/otp/check` are unauthenticated. `/login/finalize`
    /// is DPoP-bound, not Bearer-protected; no access token exists
    /// yet at that point in the flow. Pin all three so a future
    /// "always attach Bearer" interceptor can't silently leak a
    /// stale token (or, worse, send `Bearer ` empty) into login.
    func test_otpLogin_doesNotAttachAuthorizationBearer() async throws {
        let fixture = try makeFixture()

        fixture.http.install(path: "/v1/session/otp", response: .noContent)
        fixture.http.install(
            path: "/v1/session/otp/check",
            response: .json(["challenge_token": "challenge-abc"])
        )
        fixture.http.install(
            path: "/v1/session/login/finalize",
            response: .json(
                [
                    "access_token": jwt,
                    "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                ],
                headers: [HTTPHeader.refreshToken: "refresh-v1"]
            )
        )

        try await fixture.client.startOTPLogin(
            StartOTPLoginOptions(
                identifier: PreludeIdentifier(type: .emailAddress, value: "alice@example.com")
            )
        )
        _ = try await fixture.client.checkOTP("123456")

        for path in ["/v1/session/otp", "/v1/session/otp/check", "/v1/session/login/finalize"] {
            let recorded = fixture.http.requests(forPath: path)
            XCTAssertEqual(recorded.count, 1, "\(path) should be hit exactly once")
            XCTAssertNil(
                recorded.first?.value(forHTTPHeaderField: HTTPHeader.authorization),
                "\(path) must not carry Authorization"
            )
        }
    }

    // MARK: - Previous-session refresh token forwarding

    /// Re-login while a previous session's refresh token is still on
    /// disk: `/login/finalize` forwards it as `X-Refresh-Token` so the
    /// server can revoke the old session instead of leaving it dangling.
    func test_otpLogin_forwardsPreviousRefreshToken_onFinalize() async throws {
        let fixture = try makeFixture()
        try fixture.refreshTokenStore.set(
            domain: domain,
            record: RefreshTokenRecord(
                refreshToken: "previous-refresh",
                refreshTokenExpiresAt: nil
            )
        )

        fixture.http.install(
            path: "/v1/session/otp/check",
            response: .json(["challenge_token": "challenge-abc"])
        )
        fixture.http.install(
            path: "/v1/session/login/finalize",
            response: .json(
                [
                    "access_token": jwt,
                    "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                ],
                headers: [HTTPHeader.refreshToken: "refresh-v1"]
            )
        )

        _ = try await fixture.client.checkOTP("123456")

        let finalize = fixture.http.requests(forPath: "/v1/session/login/finalize")
        XCTAssertEqual(finalize.count, 1)
        XCTAssertEqual(
            finalize.first?.value(forHTTPHeaderField: HTTPHeader.refreshToken),
            "previous-refresh",
            "/login/finalize must forward the prior session's refresh token"
        )
    }

    /// First login on a clean device: nothing to revoke, so
    /// `/login/finalize` must not carry an `X-Refresh-Token` header.
    func test_otpLogin_omitsRefreshTokenHeader_whenNoPriorSession() async throws {
        let fixture = try makeFixture()

        fixture.http.install(
            path: "/v1/session/otp/check",
            response: .json(["challenge_token": "challenge-abc"])
        )
        fixture.http.install(
            path: "/v1/session/login/finalize",
            response: .json(
                [
                    "access_token": jwt,
                    "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                ],
                headers: [HTTPHeader.refreshToken: "refresh-v1"]
            )
        )

        _ = try await fixture.client.checkOTP("123456")

        let finalize = fixture.http.requests(forPath: "/v1/session/login/finalize")
        XCTAssertEqual(finalize.count, 1)
        XCTAssertNil(
            finalize.first?.value(forHTTPHeaderField: HTTPHeader.refreshToken),
            "/login/finalize must not carry X-Refresh-Token without a prior session"
        )
    }

    // MARK: - DPoP nonce harvest

    /// `/login/finalize` is the first DPoP-signed hop in OTP login.
    /// When its response carries `DPoP-Nonce`, the interceptor
    /// must persist it so the next DPoP request can include it
    /// directly. Skipping this would force a `use_dpop_nonce`
    /// challenge on the very first protected call after login.
    func test_otpLogin_harvestsDPoPNonce_fromFinalizeResponse() async throws {
        let fixture = try makeFixture()

        fixture.http.install(
            path: "/v1/session/otp/check",
            response: .json(["challenge_token": "challenge-abc"])
        )
        fixture.http.install(
            path: "/v1/session/login/finalize",
            response: .json(
                [
                    "access_token": jwt,
                    "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                ],
                headers: [
                    HTTPHeader.refreshToken: "refresh-v1",
                    HTTPHeader.dpopNonce: "nonce-from-finalize",
                ]
            )
        )

        // No nonce stored before login.
        XCTAssertNil(try fixture.keyStore.getNonce(domain: domain))

        _ = try await fixture.client.checkOTP("123456")

        XCTAssertEqual(
            try fixture.keyStore.getNonce(domain: domain),
            "nonce-from-finalize",
            "DPoP-Nonce from /login/finalize must be harvested for reuse"
        )
    }

    // MARK: - Helpers

    private func makeFixture() throws -> Fixture {
        try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
    }
}
