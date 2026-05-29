import Foundation
@testable import PreludeAuth
import XCTest

/// Race-proofing the session accessors (``profile``, ``sessionID``,
/// ``accessToken``, ``accessTokenExpiresAt``) against the
/// ``invalidateSession()`` → accessor sequence. The accessors must
/// join any in-flight refresh before reading the cache so a caller
/// observes the post-refresh entry rather than the invalidated one
/// that sits in the cache mid-cycle.
final class SessionAccessorRaceTests: XCTestCase {
    private let refreshPath = "/v1/session/refresh"
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "session-accessor-race-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_700_000_000) }
    }

    override func tearDown() {
        domain = nil; baseURL = nil; clock = nil
        super.tearDown()
    }

    /// Accessors that race an in-flight refresh return the
    /// post-refresh entry, not the invalidated one. Without the
    /// drain, all three would surface the stale `user-v1` payload
    /// the cache still holds between `invalidateSession()` and the
    /// refresh's `cache.set`.
    func test_accessors_drainInflightRefresh_returnPostRefreshEntry() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()
        try await fixture.accessTokenCache.set(
            domain: domain,
            entry: AccessTokenEntry(accessToken: makeJWT(sub: "user-v1"), expiresAt: now + 3600)
        )

        let newJWT = makeJWT(sub: "user-v2", sid: "sid-v2")
        let newExpiresAt = now + 7200
        fixture.http.install(
            path: refreshPath,
            response: .json(
                ["access_token": newJWT, "expires_at": newExpiresAt],
                headers: [HTTPHeader.refreshToken: "refresh-v2"]
            )
        )
        fixture.http.installGate(path: refreshPath)

        // Invalidate, then drive a refresh: the inflight slot is
        // installed and suspended on the gate.
        try await fixture.client.invalidateSession()
        async let refreshUser = fixture.client.refresh()
        try await waitUntilInflight(fixture: fixture)

        async let profile = fixture.client.profile
        async let token = fixture.client.accessToken
        async let expiresAt = fixture.client.accessTokenExpiresAt

        fixture.http.releaseGate(path: refreshPath)

        let (gotProfile, gotToken, gotExpiresAt, gotUser) =
            try await (profile, token, expiresAt, refreshUser)

        XCTAssertEqual(gotUser.accessToken, newJWT)
        XCTAssertEqual(gotToken, newJWT)
        XCTAssertEqual(gotProfile?.userID, "user-v2")
        XCTAssertEqual(gotProfile?.sessionID, "sid-v2")
        XCTAssertEqual(gotExpiresAt, Date(timeIntervalSince1970: TimeInterval(newExpiresAt)))
    }

    /// Cheap-read guard: a populated, still-valid cache must NOT
    /// trigger a network call from the accessors. Regression
    /// catcher in case anyone replaces the drain-then-read with a
    /// blanket `refresh()`.
    func test_accessors_withValidCache_doNotHitNetwork() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        try await fixture.prePopulate()
        let jwt = makeJWT(sub: "user-cached", sid: "sid-cached")
        let expiresAt = now + 3600
        try await fixture.accessTokenCache.set(
            domain: domain,
            entry: AccessTokenEntry(accessToken: jwt, expiresAt: expiresAt)
        )

        let profile = await fixture.client.profile
        let token = await fixture.client.accessToken
        let exp = await fixture.client.accessTokenExpiresAt
        let sid = await fixture.client.sessionID

        XCTAssertEqual(token, jwt)
        XCTAssertEqual(profile?.userID, "user-cached")
        XCTAssertEqual(sid, "sid-cached")
        XCTAssertEqual(exp, Date(timeIntervalSince1970: TimeInterval(expiresAt)))
        XCTAssertEqual(
            fixture.http.requestCount(forPath: refreshPath), 0,
            "accessors must stay a cheap probe when cache is valid"
        )
    }

    // MARK: - Helpers

    private var now: Int {
        Int(clock().timeIntervalSince1970)
    }

    private func makeJWT(sub: String, sid: String? = nil) -> String {
        var claims: [String: Any] = ["sub": sub]
        if let sid { claims["sid"] = sid }
        return StepUpFixtures.makeChallengeToken(claims)
    }

    /// Spin until ``refresh()`` has reached the wire — at that point
    /// the inflight task is installed and parked on the HTTP gate,
    /// so any accessor entering the actor sees it.
    private func waitUntilInflight(
        fixture: Fixture,
        timeout: TimeInterval = 2,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async throws {
        let start = Date()
        while Date().timeIntervalSince(start) < timeout {
            if fixture.http.requestCount(forPath: refreshPath) >= 1 {
                return
            }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        XCTFail("timed out waiting for /refresh to be in flight", file: file, line: line)
    }
}
