import Foundation
@testable import PreludeAuth
import XCTest

/// End-to-end OTP login → logout over the mocked network.
///
/// Drives the public surface (``startOTPLogin``, ``checkOTP``,
/// ``logout``) so the proof-attachment policy, token persistence,
/// DPoP signing on `/login/finalize` and `/revoke`, and store
/// wipe all participate in a single test. Small inter-stage
/// pauses approximate real-world inter-network latency; if any
/// future state machine quietly races, the delay widens the
/// window enough for the race to surface.
final class OTPLoginLogoutE2ETests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "otp-e2e-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_700_000_000) }
    }

    override func tearDown() {
        domain = nil; baseURL = nil; clock = nil
        super.tearDown()
    }

    /// Well-formed unsigned JWT — `JWT.decode` reads the payload
    /// only. Carries `sub` so ``PreludeAuthClient/makeUser`` can
    /// hydrate a profile.
    private let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.sig"

    func test_otpLogin_thenLogout_endToEnd() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        installLoginAndLogoutSequence(fixture)

        // Stage 1: kick off OTP delivery. Unauthenticated.
        try await fixture.client.startOTPLogin(
            StartOTPLoginOptions(
                identifier: PreludeIdentifier(type: .emailAddress, value: "alice@example.com")
            )
        )
        try await Self.delayBetweenStages()
        let otpReq = try XCTUnwrap(fixture.http.requests(forPath: "/v1/session/otp").first)
        XCTAssertNil(otpReq.value(forHTTPHeaderField: HTTPHeader.dpop), "/otp must not carry DPoP")
        XCTAssertNil(otpReq.value(forHTTPHeaderField: HTTPHeader.authorization))

        // Stage 2: submit OTP code. `/otp/check` is unauthenticated;
        // `/login/finalize` is DPoP-bound.
        let user = try await fixture.client.checkOTP("123456")
        try await Self.delayBetweenStages()
        XCTAssertEqual(user.profile.userID, "user-1")

        let checkReq = try XCTUnwrap(fixture.http.requests(forPath: "/v1/session/otp/check").first)
        XCTAssertNil(checkReq.value(forHTTPHeaderField: HTTPHeader.dpop), "/otp/check must not carry DPoP")

        let finalizeReq = try XCTUnwrap(fixture.http.requests(forPath: "/v1/session/login/finalize").first)
        XCTAssertNotNil(finalizeReq.value(forHTTPHeaderField: HTTPHeader.dpop), "/login/finalize must be DPoP-signed")

        // Stores are now hydrated.
        XCTAssertEqual(
            try fixture.refreshTokenStore.get(domain: domain)?.refreshToken,
            "refresh-v1"
        )
        let cached = await fixture.accessTokenCache.getWithoutExpirationCheck(domain: domain)
        XCTAssertEqual(cached?.accessToken, jwt)

        // Stage 3: logout. `/revoke` must be DPoP-signed and carry
        // the pre-rotation refresh token. Wipes every store.
        try await fixture.client.logout()
        let revokeReq = try XCTUnwrap(fixture.http.requests(forPath: "/v1/session/revoke").first)
        XCTAssertNotNil(revokeReq.value(forHTTPHeaderField: HTTPHeader.dpop), "/revoke must be DPoP-signed")
        XCTAssertEqual(revokeReq.value(forHTTPHeaderField: HTTPHeader.refreshToken), "refresh-v1")

        try await fixture.assertWiped()
    }

    /// Same flow but with the network artificially slow. Inserts
    /// gates on each path so we can observe the in-flight states
    /// and prove the inflight refresh / logout coordination logic
    /// doesn't deadlock or skip stages.
    func test_otpLogin_thenLogout_endToEnd_withSlowNetwork() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        installLoginAndLogoutSequence(fixture)
        for path in ["/v1/session/otp", "/v1/session/otp/check", "/v1/session/login/finalize", "/v1/session/revoke"] {
            fixture.http.installGate(path: path)
        }

        async let stage1: Void = fixture.client.startOTPLogin(
            StartOTPLoginOptions(
                identifier: PreludeIdentifier(type: .emailAddress, value: "alice@example.com")
            )
        )
        try await Self.delayBetweenStages()
        fixture.http.releaseGate(path: "/v1/session/otp")
        try await stage1

        async let stage2 = fixture.client.checkOTP("123456")
        try await Self.delayBetweenStages()
        fixture.http.releaseGate(path: "/v1/session/otp/check")
        try await Self.delayBetweenStages()
        fixture.http.releaseGate(path: "/v1/session/login/finalize")
        let user = try await stage2
        XCTAssertEqual(user.profile.userID, "user-1")

        async let stage3: Void = fixture.client.logout()
        try await Self.delayBetweenStages()
        fixture.http.releaseGate(path: "/v1/session/revoke")
        try await stage3

        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/revoke"), 1)
        try await fixture.assertWiped()
    }

    // MARK: - Helpers

    private func installLoginAndLogoutSequence(_ fixture: Fixture) {
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
                headers: [
                    HTTPHeader.refreshToken: "refresh-v1",
                    HTTPHeader.refreshTokenExpiresAt: "2099-01-01T00:00:00Z",
                ]
            )
        )
        fixture.http.install(path: "/v1/session/revoke", response: .noContent)
    }

    /// 20 ms — long enough that any single-thread reordering bug
    /// would have already settled, short enough that the suite
    /// stays sub-second.
    private static func delayBetweenStages() async throws {
        try await Task.sleep(nanoseconds: 20_000_000)
    }
}
