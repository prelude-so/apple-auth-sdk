import Foundation

/// Auth-state surface the ``AutoRefreshInterceptor`` calls into to
/// fetch the current bearer, invalidate it on a 401, and trigger a
/// refresh.
protocol SessionRefreshing: Sendable {
    /// Cached access token, ignoring expiration. `nil` when no
    /// session is active; the interceptor then omits `Authorization`.
    func currentAccessToken() async throws -> String?

    /// Mark the cached access token stale after a 401, so the
    /// next protected call refreshes.
    func invalidateCurrentToken() async throws

    /// Refresh and return the new access token. Concurrent
    /// callers must be coalesced inside the conformer — refresh
    /// tokens are single-use and a double-spend revokes the
    /// session.
    func refreshAccessToken() async throws -> String
}

// MARK: - Production conformance

extension PreludeAuthClient.Impl: SessionRefreshing {
    func currentAccessToken() async throws -> String? {
        try requireUnsealed()
        return await accessTokenCache.getWithoutExpirationCheck(domain: domain)?.accessToken
    }

    func invalidateCurrentToken() async throws {
        try await invalidateSession()
    }

    func refreshAccessToken() async throws -> String {
        try await refresh().accessToken
    }
}
