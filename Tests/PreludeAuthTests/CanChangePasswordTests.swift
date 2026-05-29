import Foundation
@testable import PreludeAuth
import XCTest

final class CanChangePasswordTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "can-change-pwd-test-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    // Tokens carrying different shapes of the `scope` claim. Built
    // statically so the test reads as a table; payload bodies are
    // documented inline.

    /// `{"sub":"user-1","sid":"sess-1","scope":"prld:pwd:write"}`
    private let tokenWithScope =
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEiLCJzaWQiOiJzZXNzLTEiLCJzY29wZSI6InBybGQ6cHdkOndyaXRlIn0.sig"

    /// Scope present alongside others: must still match.
    /// `{"sub":"user-1","sid":"sess-1","scope":"prld:foo:read prld:pwd:write prld:bar:write"}`
    private let tokenWithScopeAmongMany = "eyJhbGciOiJIUzI1NiJ9."
        + "eyJzdWIiOiJ1c2VyLTEiLCJzaWQiOiJzZXNzLTEi"
        + "LCJzY29wZSI6InBybGQ6Zm9vOnJlYWQgcHJsZDpw"
        + "d2Q6d3JpdGUgcHJsZDpiYXI6d3JpdGUifQ."
        + "sig"

    /// `{"sub":"user-1","sid":"sess-1","scope":"prld:foo:read"}`
    private let tokenWithOtherScope =
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEiLCJzaWQiOiJzZXNzLTEiLCJzY29wZSI6InBybGQ6Zm9vOnJlYWQifQ.sig"

    /// `{"sub":"user-1","sid":"sess-1"}` — no `scope` claim at all.
    private let tokenWithoutScope =
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEiLCJzaWQiOiJzZXNzLTEifQ.sig"

    /// `{"sub":"user-1","sid":"sess-1","scope":42}` — `scope` present
    /// but not a string.
    private let tokenWithMalformedScope =
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEiLCJzaWQiOiJzZXNzLTEiLCJzY29wZSI6NDJ9.sig"

    // MARK: - Scope present

    func test_canChangePassword_scopePresent_returnsTrue() async throws {
        let fixture = try await makeFixtureWithRefresh(returning: tokenWithScope)
        let result = try await fixture.client.canChangePassword()
        XCTAssertTrue(result)
    }

    func test_canChangePassword_scopeAmongMany_returnsTrue() async throws {
        let fixture = try await makeFixtureWithRefresh(returning: tokenWithScopeAmongMany)
        let result = try await fixture.client.canChangePassword()
        XCTAssertTrue(result)
    }

    // MARK: - Scope absent

    func test_canChangePassword_scopeAbsent_returnsFalse() async throws {
        let fixture = try await makeFixtureWithRefresh(returning: tokenWithOtherScope)
        let result = try await fixture.client.canChangePassword()
        XCTAssertFalse(result)
    }

    func test_canChangePassword_missingScopeClaim_returnsFalse() async throws {
        let fixture = try await makeFixtureWithRefresh(returning: tokenWithoutScope)
        let result = try await fixture.client.canChangePassword()
        XCTAssertFalse(result)
    }

    func test_canChangePassword_malformedScopeClaim_returnsFalse() async throws {
        let fixture = try await makeFixtureWithRefresh(returning: tokenWithMalformedScope)
        let result = try await fixture.client.canChangePassword()
        XCTAssertFalse(result)
    }

    // MARK: - Refresh failure propagates

    func test_canChangePassword_refreshFails_throws() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()

        fixture.http.install(
            path: "/v1/session/refresh",
            response: .json(
                ["code": "internal_server_error", "message": "boom"],
                statusCode: 500
            )
        )

        do {
            _ = try await fixture.client.canChangePassword()
            XCTFail("expected refresh failure to throw")
        } catch {
            // Any throw is acceptable — caller distinguishes
            // "refresh failed" from "no scope" via throw vs false.
        }
    }

    // MARK: - Invalidate-then-refresh is load-bearing

    /// Even with a fresh-looking cached token in place, the helper
    /// must invalidate and hit `/refresh` — a cached token can carry
    /// a server-consumed scope.
    func test_canChangePassword_alwaysHitsNetwork_evenWithFreshCache() async throws {
        let fixture = try await makeFixtureWithRefresh(returning: tokenWithScope)

        _ = try await fixture.client.canChangePassword()

        XCTAssertEqual(
            fixture.http.requestCount(forPath: "/v1/session/refresh"),
            1,
            "canChangePassword must invalidate + refresh even when the cache is warm"
        )
    }

    // MARK: - Helpers

    /// Pre-populated fixture with `/refresh` installed to return
    /// `token` as the freshly-minted access token.
    private func makeFixtureWithRefresh(returning token: String) async throws -> Fixture {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()
        fixture.http.install(
            path: "/v1/session/refresh",
            response: .json(
                [
                    "access_token": token,
                    "expires_at": Int(clock().timeIntervalSince1970) + 3600,
                ],
                headers: [HTTPHeader.refreshToken: "refresh-v2"]
            )
        )
        return fixture
    }
}
