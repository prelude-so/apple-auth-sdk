import Foundation
@testable import PreludeAuth
import XCTest

/// Pre-wired ``PreludeAuthClient`` + backing stores + stub HTTP
/// session, so each test focuses on behaviour rather than setup.
struct Fixture {
    let client: PreludeAuthClient
    let http: StubHTTPSession
    let keyStore: SoftwareDPoPKeyStore
    let refreshTokenStore: RefreshTokenStore
    let accessTokenCache: AccessTokenCache
    let domain: String
    let clock: NowProvider

    static func make(
        domain: String,
        baseURL: URL,
        clock: @escaping NowProvider,
        backend: KeychainBackend = InMemoryKeychainBackend()
    ) throws -> Self {
        let keyStore = SoftwareDPoPKeyStore(backend: backend)
        let refreshTokenStore = RefreshTokenStore(keychain: backend)
        let accessTokenCache = AccessTokenCache(clock: clock, keychain: backend)
        let http = StubHTTPSession()

        let client = try PreludeAuthClient(
            baseURL: baseURL,
            hostOverride: nil,
            signalsDispatcher: nil,
            timeout: 1,
            httpSession: http,
            clock: clock,
            keyStore: keyStore,
            refreshTokenStore: refreshTokenStore,
            accessTokenCache: accessTokenCache
        )

        return Self(
            client: client,
            http: http,
            keyStore: keyStore,
            refreshTokenStore: refreshTokenStore,
            accessTokenCache: accessTokenCache,
            domain: domain,
            clock: clock
        )
    }

    /// Populate every domain-scoped store so logout/refresh tests
    /// have something to revoke, wipe, or rotate.
    func prePopulate(nonce: String? = nil, accessTokenExpired: Bool = false) async throws {
        _ = try keyStore.getOrCreate(domain: domain)
        if let nonce { try keyStore.setNonce(domain: domain, nonce: nonce) }
        try refreshTokenStore.set(
            domain: domain,
            record: RefreshTokenRecord(refreshToken: "refresh-v1", refreshTokenExpiresAt: nil)
        )
        let now = Int(clock().timeIntervalSince1970)
        try await accessTokenCache.set(
            domain: domain,
            entry: AccessTokenEntry(
                accessToken: "access-v1",
                expiresAt: accessTokenExpired ? now - 3600 : now + 3600
            )
        )
    }

    /// Assert that every domain-scoped store is empty.
    func assertWiped(file: StaticString = #filePath, line: UInt = #line) async throws {
        XCTAssertNil(try keyStore.get(domain: domain), "DPoP key", file: file, line: line)
        XCTAssertNil(try keyStore.getNonce(domain: domain), "nonce", file: file, line: line)
        XCTAssertNil(try keyStore.getClockSkew(domain: domain), "clock skew", file: file, line: line)
        XCTAssertNil(try refreshTokenStore.get(domain: domain), "refresh token", file: file, line: line)
        let cached = await accessTokenCache.getWithoutExpirationCheck(domain: domain)
        XCTAssertNil(cached, "access token", file: file, line: line)
    }
}
