import Foundation
@testable import PreludeAuth
import XCTest

/// Header policy for the step-up `/otp/check` hop:
///
///   - DPoP proof has `jti` = challenge token's jti (server can
///     pin the proof to this challenge), no `nonce` claim
///     (challenge requests are one-shot, not in the nonce dance).
///   - No `Authorization: Bearer …` — the challenge token in the
///     body is the entire credential.
final class StepUpHeadersTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "stepup-headers-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    override func tearDown() {
        domain = nil; baseURL = nil; clock = nil
        super.tearDown()
    }

    private var otpChallengeToken: String {
        StepUpFixtures.makeChallengeToken([
            "challenge_id": "chal-1", "current_step": "verify_email",
            "jti": "jti-otp", "exp": 2_000_000,
        ])
    }

    // MARK: - DPoP proof shape

    /// Pin both jti binding (proof tied to this challenge) and
    /// the nonce omission. Splitting these into two tests would
    /// duplicate setup; the two facts share one round-trip.
    func test_submitStepUpOTP_dpopProof_carriesChallengeJti_andNoNonce() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()
        installLoop(fixture: fixture)

        let challenge = try await fixture.client.requestStepUp(scope: "prld:pwd:write")
        _ = try? await fixture.client.submitStepUpOTP(challenge, code: "123456")

        let req = try XCTUnwrap(fixture.http.requests(forPath: "/v1/session/otp/check").last)
        let proof = try XCTUnwrap(req.value(forHTTPHeaderField: HTTPHeader.dpop))
        let claims = try StepUpFixtures.decodeJWTPayload(proof)
        XCTAssertEqual(claims["jti"] as? String, "jti-otp")
        XCTAssertNil(claims["nonce"], "challenge-scoped proofs must not carry a nonce")
    }

    /// `/otp/check` (step-up) authenticates via the challenge
    /// token in the body; no Bearer must ride along — even if a
    /// valid access token sits in the cache.
    func test_submitStepUpOTP_doesNotAttachAuthorizationBearer() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate() // populates a valid access token
        installLoop(fixture: fixture)

        let challenge = try await fixture.client.requestStepUp(scope: "prld:pwd:write")
        _ = try? await fixture.client.submitStepUpOTP(challenge, code: "123456")

        let req = fixture.http.requests(forPath: "/v1/session/otp/check").last
        XCTAssertNil(
            req?.value(forHTTPHeaderField: HTTPHeader.authorization),
            "step-up /otp/check must not carry Authorization"
        )
    }

    /// Persisted clock skew on the keystore must flow through to
    /// the challenge proof's `iat`. The challenge interceptor
    /// reads the same field the regular DPoP retry path persisted
    /// earlier.
    func test_submitStepUpOTP_dpopProof_appliesPersistedClockSkew() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()
        installLoop(fixture: fixture)
        let persistedSkew: TimeInterval = 45
        try fixture.keyStore.setClockSkew(domain: domain, skew: persistedSkew)

        let challenge = try await fixture.client.requestStepUp(scope: "prld:pwd:write")
        _ = try? await fixture.client.submitStepUpOTP(challenge, code: "123456")

        let req = try XCTUnwrap(fixture.http.requests(forPath: "/v1/session/otp/check").last)
        let proof = try XCTUnwrap(req.value(forHTTPHeaderField: HTTPHeader.dpop))
        let iat = try XCTUnwrap(StepUpFixtures.decodeJWTPayload(proof)["iat"] as? Int)
        XCTAssertEqual(
            TimeInterval(iat),
            Date().addingTimeInterval(persistedSkew).timeIntervalSince1970,
            accuracy: 3.0,
            "challenge proof iat must carry the persisted skew"
        )
    }

    // MARK: - Helpers

    /// Loop /otp/check back to the same OTP step so the post-
    /// completion refresh path doesn't fire — header inspection
    /// only needs the request, not the full flow.
    private func installLoop(fixture: Fixture) {
        fixture.http.install(
            path: "/v1/session/stepup/request",
            response: .json(["status": "continue", "challenge_token": otpChallengeToken])
        )
        fixture.http.install(
            path: "/v1/session/otp/check",
            response: .json(["challenge_token": otpChallengeToken])
        )
    }
}
