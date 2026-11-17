import Foundation

/// Auth-state surface the ``AutoRefreshInterceptor`` calls into to
/// fetch the current bearer and recover from a 401.
protocol SessionRefreshing: Sendable {
    /// Cached access token, ignoring expiration. `nil` when no
    /// session is active; the interceptor then omits `Authorization`.
    func currentAccessToken() async throws -> String?

    /// Mark `token` stale after a 401 if it is still the cached one.
    /// Throws `sessionLocked` on a sealed client, also when `token`
    /// is nil.
    func invalidateAccessToken(ifMatching token: String?) async throws

    /// Return a valid access token, refreshing when needed.
    /// Concurrent callers must be coalesced inside the conformer —
    /// refresh tokens are single-use and a double-spend revokes the
    /// session.
    func refreshAccessToken() async throws -> String
}

// MARK: - Production conformance

extension PreludeAuthClient.Impl: SessionRefreshing {
    func currentAccessToken() async throws -> String? {
        try requireUnsealed()
        return await accessTokenCache.getWithoutExpirationCheck(domain: domain)?.accessToken
    }

    func invalidateAccessToken(ifMatching token: String?) async throws {
        try requireUnsealed()
        guard let token, !token.isEmpty else { return }
        try await accessTokenCache.invalidate(domain: domain, ifMatching: token)
    }

    func refreshAccessToken() async throws -> String {
        try await refresh().accessToken
    }
}
