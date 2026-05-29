import Foundation
@testable import PreludeAuth
import XCTest

/// Pins the DPoP proof structure (RFC 9449 §4.2): `htm`, `htu`,
/// `iat`, `jti`, and the `nonce`-presence rules. Operates on the
/// proof JWT directly so a regression in any single claim trips
/// here rather than as a server-side rejection.
final class DPoPProofTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "dpop-proof-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    override func tearDown() {
        domain = nil; baseURL = nil; clock = nil
        super.tearDown()
    }

    // MARK: - Builder-level (claim shape)

    func test_proof_htm_matchesMethodVerbatim() throws {
        let key = try freshKey()
        for method in ["POST", "GET", "PATCH"] {
            let proof = try DefaultDPoPProofBuilder().create(
                key: key, method: method,
                url: XCTUnwrap(URL(string: "https://api.example.com/x")),
                nonce: nil, jti: nil, now: Date()
            )
            let claims = try StepUpFixtures.decodeJWTPayload(proof)
            XCTAssertEqual(claims["htm"] as? String, method)
        }
    }

    /// Mixed-case input to `htuURL` must produce a lowercased
    /// scheme + host (RFC 3986 §6.2.2.1).
    func test_htuURL_lowercasesSchemeAndHost() throws {
        let request = try URLRequest(url: XCTUnwrap(URL(string: "HTTPS://API.Example.COM/v1/x")))
        let htu = try XCTUnwrap(DPoPInterceptor.htuURL(for: request))
        XCTAssertEqual(htu.absoluteString, "https://api.example.com/v1/x")
    }

    func test_htuURL_lowercasesHostOverride() throws {
        var request = try URLRequest(url: XCTUnwrap(URL(string: "https://127.0.0.1/v1/x")))
        request.setValue("Sessdev.Example.COM:443", forHTTPHeaderField: HTTPHeader.host)
        let htu = try XCTUnwrap(DPoPInterceptor.htuURL(for: request))
        XCTAssertEqual(htu.absoluteString, "https://sessdev.example.com:443/v1/x")
    }

    func test_proof_iat_isWithin60sOfNow() throws {
        let key = try freshKey()
        let now = Date()
        let proof = try DefaultDPoPProofBuilder().create(
            key: key, method: "POST",
            url: XCTUnwrap(URL(string: "https://x/y")),
            nonce: nil, jti: nil, now: now
        )
        let iat = try XCTUnwrap(StepUpFixtures.decodeJWTPayload(proof)["iat"] as? Int)
        XCTAssertEqual(TimeInterval(iat), now.timeIntervalSince1970, accuracy: 60)
    }

    /// Two consecutive proofs must have distinct, UUID-shaped jtis.
    func test_proof_jti_isFreshUUID_perCall() throws {
        let key = try freshKey()
        let url = try XCTUnwrap(URL(string: "https://x/y"))
        let firstProof = try DefaultDPoPProofBuilder().create(
            key: key, method: "POST", url: url, nonce: nil, jti: nil, now: Date()
        )
        let secondProof = try DefaultDPoPProofBuilder().create(
            key: key, method: "POST", url: url, nonce: nil, jti: nil, now: Date()
        )
        let jti1 = try XCTUnwrap(StepUpFixtures.decodeJWTPayload(firstProof)["jti"] as? String)
        let jti2 = try XCTUnwrap(StepUpFixtures.decodeJWTPayload(secondProof)["jti"] as? String)
        XCTAssertNotEqual(jti1, jti2)
        XCTAssertNotNil(UUID(uuidString: jti1))
        XCTAssertNotNil(UUID(uuidString: jti2))
    }

    func test_proof_nonce_omittedWhenNil_includedWhenSet() throws {
        let key = try freshKey()
        let url = try XCTUnwrap(URL(string: "https://x/y"))
        let withoutNonce = try DefaultDPoPProofBuilder().create(
            key: key, method: "POST", url: url, nonce: nil, jti: nil, now: Date()
        )
        let withNonce = try DefaultDPoPProofBuilder().create(
            key: key, method: "POST", url: url, nonce: "n42", jti: nil, now: Date()
        )
        XCTAssertNil(try StepUpFixtures.decodeJWTPayload(withoutNonce)["nonce"])
        XCTAssertEqual(
            try StepUpFixtures.decodeJWTPayload(withNonce)["nonce"] as? String, "n42"
        )
    }

    // MARK: - clockSkewSec arithmetic

    /// The skew is `serverTime - localTime`; a positive value
    /// advances `iat` into the server's frame.
    func test_proof_iat_appliesPositiveClockSkew() throws {
        let key = try freshKey()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let proof = try DefaultDPoPProofBuilder().create(
            key: key, method: "POST",
            url: XCTUnwrap(URL(string: "https://x/y")),
            nonce: nil, jti: nil, now: now, clockSkewSec: 30
        )
        let iat = try XCTUnwrap(StepUpFixtures.decodeJWTPayload(proof)["iat"] as? Int)
        XCTAssertEqual(iat, 1_700_000_030)
    }

    func test_proof_iat_appliesNegativeClockSkew() throws {
        let key = try freshKey()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let proof = try DefaultDPoPProofBuilder().create(
            key: key, method: "POST",
            url: XCTUnwrap(URL(string: "https://x/y")),
            nonce: nil, jti: nil, now: now, clockSkewSec: -45
        )
        let iat = try XCTUnwrap(StepUpFixtures.decodeJWTPayload(proof)["iat"] as? Int)
        XCTAssertEqual(iat, 1_699_999_955)
    }

    func test_proof_iat_zeroClockSkewIsNoOp() throws {
        let key = try freshKey()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let proof = try DefaultDPoPProofBuilder().create(
            key: key, method: "POST",
            url: XCTUnwrap(URL(string: "https://x/y")),
            nonce: nil, jti: nil, now: now, clockSkewSec: 0
        )
        let iat = try XCTUnwrap(StepUpFixtures.decodeJWTPayload(proof)["iat"] as? Int)
        XCTAssertEqual(iat, 1_700_000_000)
    }

    // MARK: - End-to-end (interceptor + use_dpop_nonce retry)

    /// First call to a fresh domain (no cached nonce) must produce
    /// a proof without `nonce`. The retry triggered by
    /// `use_dpop_nonce` must mint a fresh `jti` distinct from the
    /// first proof.
    func test_useDpopNonceRetry_freshNonce_freshJti() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)

        let challenge = try JSONSerialization.data(withJSONObject: [
            "code": "use_dpop_nonce", "message": "rotate",
        ])
        fixture.http.installSequence(
            path: "/v1/session/refresh",
            responses: [
                StubHTTPSession.CannedResponse(
                    statusCode: 400, body: challenge,
                    headers: [
                        "Content-Type": "application/json",
                        HTTPHeader.dpopNonce: "n1",
                    ]
                ),
                .json(
                    [
                        "access_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.s",
                        "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                    ],
                    headers: [HTTPHeader.refreshToken: "r2"]
                ),
            ]
        )
        try await fixture.prePopulate(accessTokenExpired: true)

        _ = try await fixture.client.refresh()

        let reqs = fixture.http.requests(forPath: "/v1/session/refresh")
        XCTAssertEqual(reqs.count, 2)

        let firstProof = try StepUpFixtures.decodeJWTPayload(
            XCTUnwrap(reqs[0].value(forHTTPHeaderField: HTTPHeader.dpop))
        )
        let secondProof = try StepUpFixtures.decodeJWTPayload(
            XCTUnwrap(reqs[1].value(forHTTPHeaderField: HTTPHeader.dpop))
        )
        XCTAssertNil(firstProof["nonce"], "first call to fresh domain has no cached nonce")
        XCTAssertEqual(secondProof["nonce"] as? String, "n1", "retry uses the harvested nonce")
        XCTAssertNotEqual(firstProof["jti"] as? String, secondProof["jti"] as? String)
    }

    // MARK: - Helpers

    private func freshKey() throws -> DPoPKey {
        try SoftwareDPoPKeyStore(backend: InMemoryKeychainBackend())
            .getOrCreate(domain: "dpop-proof-key-\(UUID().uuidString)")
    }
}
