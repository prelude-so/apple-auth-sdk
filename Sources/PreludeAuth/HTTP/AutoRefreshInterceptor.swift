import Foundation

/// Attaches `Authorization: Bearer <access token>` and recovers from
/// 401 responses by expiring the rejected token (only if it is still
/// cached), refreshing when needed, and retrying once.
/// If the refresh fails, returns the original 401 (not the
/// retry response, never a thrown error) so upstream retry loops
/// treat auth failure as non-transient.
struct AutoRefreshInterceptor: Interceptor {
    let refresher: any SessionRefreshing

    func intercept(
        _ request: URLRequest,
        next: SendFunction
    ) async throws -> (Data, HTTPURLResponse) {
        var initialRequest = request
        // Omit `Authorization` entirely when no token is cached —
        // strict proxies reject `Bearer ` (empty) before the
        // server can return a 401, breaking the refresh path.
        let sentToken = try await refresher.currentAccessToken()
        if let sentToken, !sentToken.isEmpty {
            initialRequest.setValue("Bearer \(sentToken)", forHTTPHeaderField: HTTPHeader.authorization)
        }

        let (data, response) = try await next(initialRequest)

        guard response.statusCode == 401 else {
            return (data, response)
        }

        // A sibling caller may have refreshed while our 401 was in
        // flight: then its token is kept and returned without a new
        // refresh. Outside the `do`: a storage failure or
        // `sessionLocked` must reach the caller, not look like a 401.
        try await refresher.invalidateAccessToken(ifMatching: sentToken)

        let newToken: String
        do {
            newToken = try await refresher.refreshAccessToken()
        } catch {
            // Refresh failed — return the original 401 so upstream
            // retry loops see auth as non-transient. Errors on the
            // post-refresh retry below propagate so callers can
            // distinguish transport from auth issues.
            return (data, response)
        }

        var retryRequest = request
        retryRequest.setValue("Bearer \(newToken)", forHTTPHeaderField: HTTPHeader.authorization)
        return try await next(retryRequest)
    }
}
