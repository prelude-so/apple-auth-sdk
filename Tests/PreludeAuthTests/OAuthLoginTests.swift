import Foundation
@testable import PreludeAuth
import XCTest

final class OAuthLoginTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "oauth-test-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    /// Well-formed, unsigned JWT — `JWT.decode` reads the payload only.
    private let accessJWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.sig"

    private func makeToken(payload: [String: Any]) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: payload)
        let b64 = data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "eyJhbGciOiJIUzI1NiJ9.\(b64).sig"
    }

    /// A context for finalize paths that throw before the verifier is read.
    private func anyContext() -> OAuthLoginContext {
        OAuthLoginContext(
            authorizationURL: URL(string: "https://provider.example/auth")!,
            codeVerifier: "verifier"
        )
    }

    private static func json(_ data: Data?) throws -> [String: Any] {
        let raw = try XCTUnwrap(data)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: raw) as? [String: Any])
    }

    // MARK: - Initiate

    func test_initiate_sendsPkceChallenge_andReturnsAuthorizationURL() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        fixture.http.install(
            path: "/v1/session/login/oauth/google/authorize",
            response: .json(["authorization_url": "https://provider.example/auth?state=s1"])
        )

        let context = try await fixture.client.initiateOAuthLogin(
            InitiateOAuthLoginOptions(provider: .google, redirectURI: "demo://oauth")
        )

        XCTAssertEqual(context.authorizationURL.absoluteString, "https://provider.example/auth?state=s1")
        let body = try Self.json(
            fixture.http.requests(forPath: "/v1/session/login/oauth/google/authorize").first?.httpBody
        )
        XCTAssertEqual(body["redirect_uri"] as? String, "demo://oauth")
        XCTAssertEqual(body["code_challenge_method"] as? String, "S256")
        XCTAssertNotNil(body["code_challenge"] as? String)
    }

    func test_initiate_invalidAuthorizationURL_throws() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        fixture.http.install(
            path: "/v1/session/login/oauth/google/authorize",
            response: .json([:])
        )

        do {
            _ = try await fixture.client.initiateOAuthLogin(
                InitiateOAuthLoginOptions(provider: .google, redirectURI: "demo://oauth")
            )
            XCTFail("expected generic error")
        } catch let PreludeAuthError.generic(code, _) {
            XCTAssertEqual(code, "invalid_authorization_url")
        }
    }

    // MARK: - Finalize: PKCE binding

    func test_finalize_bindsVerifierToInitiateChallenge() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        fixture.http.install(
            path: "/v1/session/login/oauth/google/authorize",
            response: .json(["authorization_url": "https://provider.example/auth"])
        )
        fixture.http.install(
            path: "/v1/session/login/finalize",
            response: .json([
                "access_token": accessJWT,
                "expires_at": Int(clock().timeIntervalSince1970) + 3600,
            ])
        )

        let context = try await fixture.client.initiateOAuthLogin(
            InitiateOAuthLoginOptions(provider: .google, redirectURI: "demo://oauth")
        )
        let token = try makeToken(payload: ["sub": "user-1"])
        let result = try await fixture.client.finalizeOAuthLogin(context, challengeToken: token)

        guard case let .loggedIn(user) = result else {
            XCTFail("expected loggedIn")
            return
        }
        XCTAssertEqual(user.profile.userID, "user-1")

        let authorizeBody = try Self.json(
            fixture.http.requests(forPath: "/v1/session/login/oauth/google/authorize").first?.httpBody
        )
        let finalizeBody = try Self.json(
            fixture.http.requests(forPath: "/v1/session/login/finalize").first?.httpBody
        )
        let challenge = try XCTUnwrap(authorizeBody["code_challenge"] as? String)
        let verifier = try XCTUnwrap(finalizeBody["code_verifier"] as? String)
        XCTAssertEqual(challenge, PKCE.codeChallenge(for: verifier))
        XCTAssertEqual(finalizeBody["challenge_token"] as? String, token)
    }

    /// Two interleaved logins each keep their own PKCE verifier — a
    /// later initiate cannot clobber an earlier flow's secret.
    func test_concurrentLogins_doNotShareVerifier() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        fixture.http.install(
            path: "/v1/session/login/oauth/google/authorize",
            response: .json(["authorization_url": "https://provider.example/auth"])
        )
        fixture.http.install(
            path: "/v1/session/login/finalize",
            response: .json([
                "access_token": accessJWT,
                "expires_at": Int(clock().timeIntervalSince1970) + 3600,
            ])
        )

        // Both flows initiate before either finalizes — the race window.
        let ctxA = try await fixture.client.initiateOAuthLogin(
            InitiateOAuthLoginOptions(provider: .google, redirectURI: "demo://oauth")
        )
        let ctxB = try await fixture.client.initiateOAuthLogin(
            InitiateOAuthLoginOptions(provider: .google, redirectURI: "demo://oauth")
        )

        let token = try makeToken(payload: ["sub": "user-1"])
        _ = try await fixture.client.finalizeOAuthLogin(ctxA, challengeToken: token)
        _ = try await fixture.client.finalizeOAuthLogin(ctxB, challengeToken: token)

        let authorizeBodies = try fixture.http
            .requests(forPath: "/v1/session/login/oauth/google/authorize")
            .map { try Self.json($0.httpBody) }
        let finalizeBodies = try fixture.http
            .requests(forPath: "/v1/session/login/finalize")
            .map { try Self.json($0.httpBody) }
        XCTAssertEqual(authorizeBodies.count, 2)
        XCTAssertEqual(finalizeBodies.count, 2)

        // Each finalize carried the verifier from its own initiate.
        let challengeA = try XCTUnwrap(authorizeBodies[0]["code_challenge"] as? String)
        let challengeB = try XCTUnwrap(authorizeBodies[1]["code_challenge"] as? String)
        let verifierA = try XCTUnwrap(finalizeBodies[0]["code_verifier"] as? String)
        let verifierB = try XCTUnwrap(finalizeBodies[1]["code_verifier"] as? String)
        XCTAssertEqual(PKCE.codeChallenge(for: verifierA), challengeA)
        XCTAssertEqual(PKCE.codeChallenge(for: verifierB), challengeB)
        XCTAssertNotEqual(verifierA, verifierB)
    }

    // MARK: - Finalize: errors and OTP link

    func test_finalize_emptyToken_throwsMissingChallengeToken() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        do {
            _ = try await fixture.client.finalizeOAuthLogin(anyContext(), challengeToken: "")
            XCTFail("expected missingChallengeToken")
        } catch PreludeAuthError.missingChallengeToken {
            // expected
        }
    }

    func test_finalize_malformedToken_throwsInvalidChallengeToken() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        do {
            _ = try await fixture.client.finalizeOAuthLogin(anyContext(), challengeToken: "not-a-jwt")
            XCTFail("expected invalidChallengeToken")
        } catch PreludeAuthError.invalidChallengeToken {
            // expected
        }
    }

    func test_finalize_oauthEmailLink_sendsOTP_andReturnsOtpRequired() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        fixture.http.install(
            path: "/v1/session/otp",
            response: StubHTTPSession.CannedResponse(
                statusCode: 204,
                body: Data(),
                headers: [HTTPHeader.verificationToken: "verify-token-1"]
            )
        )
        let token = try makeToken(payload: [
            "grant_mode": "oauth-email-link",
            "metadata": ["oauth_email": "person@example.com"],
        ])

        let result = try await fixture.client.finalizeOAuthLogin(anyContext(), challengeToken: token)

        guard case let .otpRequired(challenge, email) = result else {
            XCTFail("expected otpRequired")
            return
        }
        // The resumable handle captures the verification token from the
        // /otp response, not the challenge token.
        XCTAssertEqual(challenge.verificationToken, "verify-token-1")
        XCTAssertEqual(email, "person@example.com")

        // The verification code is delivered via /otp, carrying the
        // challenge token; no session is established until it is checked.
        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/otp"), 1)
        let otpBody = try Self.json(
            fixture.http.requests(forPath: "/v1/session/otp").first?.httpBody
        )
        XCTAssertEqual(otpBody["challenge_token"] as? String, token)
        XCTAssertEqual(fixture.http.requestCount(forPath: "/v1/session/login/finalize"), 0)
    }

    func test_finalize_oauthEmailLink_missingVerificationToken_throws() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        // /otp succeeds but omits the verification token header.
        fixture.http.install(path: "/v1/session/otp", response: .noContent)
        let token = try makeToken(payload: ["grant_mode": "oauth-email-link"])

        do {
            _ = try await fixture.client.finalizeOAuthLogin(anyContext(), challengeToken: token)
            XCTFail("expected generic error")
        } catch let PreludeAuthError.generic(code, _) {
            XCTAssertEqual(code, "missing_verification_token")
        }
    }

    func test_checkOAuthEmailOTP_replaysVerificationToken_andFinalizes() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        fixture.http.install(
            path: "/v1/session/otp",
            response: StubHTTPSession.CannedResponse(
                statusCode: 204,
                body: Data(),
                headers: [HTTPHeader.verificationToken: "verify-token-1"]
            )
        )
        let linkToken = try makeToken(payload: [
            "grant_mode": "oauth-email-link",
            "metadata": ["oauth_email": "person@example.com"],
        ])
        let loginToken = try makeToken(payload: ["sub": "user-1"])
        fixture.http.install(
            path: "/v1/session/otp/check",
            response: .json(["challenge_token": loginToken])
        )
        fixture.http.install(
            path: "/v1/session/login/finalize",
            response: .json([
                "access_token": accessJWT,
                "expires_at": Int(clock().timeIntervalSince1970) + 3600,
            ])
        )

        guard case let .otpRequired(challenge, _) = try await fixture.client.finalizeOAuthLogin(
            anyContext(), challengeToken: linkToken
        ) else {
            XCTFail("expected otpRequired")
            return
        }

        let user = try await fixture.client.checkOAuthEmailOTP("123456", resuming: challenge)
        XCTAssertEqual(user.profile.userID, "user-1")

        // The check replays the captured verification token and stays
        // session-less (no DPoP); the body authenticates via that token,
        // not a challenge token.
        let checkReq = try XCTUnwrap(fixture.http.requests(forPath: "/v1/session/otp/check").first)
        XCTAssertEqual(checkReq.value(forHTTPHeaderField: HTTPHeader.verificationToken), "verify-token-1")
        XCTAssertNil(checkReq.value(forHTTPHeaderField: HTTPHeader.dpop))
        let checkBody = try Self.json(checkReq.httpBody)
        XCTAssertEqual(checkBody["code"] as? String, "123456")
        XCTAssertNil(checkBody["challenge_token"])

        // login/finalize establishes the DPoP-bound session.
        let finalizeReq = try XCTUnwrap(fixture.http.requests(forPath: "/v1/session/login/finalize").first)
        XCTAssertNotNil(finalizeReq.value(forHTTPHeaderField: HTTPHeader.dpop))
        let finalizeBody = try Self.json(finalizeReq.httpBody)
        XCTAssertEqual(finalizeBody["challenge_token"] as? String, loginToken)
    }

    func test_oauthEmailChallenge_redactsVerificationToken() {
        let challenge = OAuthEmailChallenge(verificationToken: "verify.SECRET.tok")

        let printed = "\(challenge)"
        let dbg = String(reflecting: challenge)
        var dumped = ""
        dump(challenge, to: &dumped)

        for surface in [printed, dbg, dumped] {
            XCTAssertFalse(surface.contains("verify.SECRET.tok"), "leaked verification token: \(surface)")
            XCTAssertTrue(surface.contains("redacted"))
        }
    }
}
