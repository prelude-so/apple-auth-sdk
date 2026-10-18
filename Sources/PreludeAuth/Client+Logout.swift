import Foundation

// MARK: - Public facade

extension PreludeAuthClient {
    /// Revoke the current session on the server and wipe every
    /// domain-scoped credential this client owns.
    ///
    /// Local state is wiped before `POST /revoke` fires. A failed
    /// server round-trip therefore still leaves the client locally
    /// logged out; concurrent ``refresh()`` can't resurrect the
    /// session — its target stores are already empty.
    public func logout() async throws {
        try await impl.logout()
    }
}

// MARK: - Implementation

extension PreludeAuthClient.Impl {
    func logout() async throws {
        // Wait for any in-flight refresh so our snapshot reads
        // the rotated refresh token, not the pre-rotation one.
        if let inflight = inflightRefresh {
            _ = try? await inflight.value
        }

        if let existing = inflightLogout {
            try await existing.value
            return
        }

        let task = Task<Void, Error> { try await self.doLogout() }
        inflightLogout = task
        defer { inflightLogout = nil }
        try await task.value
    }

    private func doLogout() async throws {
        // Snapshot what /revoke needs before wiping the stores so the
        // request can still be DPoP-signed afterwards. `try?` is
        // load-bearing: a read can fail on a corrupted Keychain item
        // that `delete` still clears, so the wipe must run regardless.
        let dpopHandle = try? keyStore.get(domain: domain)
        let dpopNonce = try? keyStore.getNonce(domain: domain)
        let dpopSkewSec = (try? keyStore.getClockSkew(domain: domain)) ?? 0
        let refreshRecord = try? refreshTokenStore.get(domain: domain)
        let refreshToken = refreshRecord?.refreshToken

        let wipeError: Error?
        do {
            try await clearAllStores()
            wipeError = nil
        } catch {
            wipeError = error
        }

        // Bump AFTER the wipe: a refresh that snapshotted pre-wipe
        // tokens holds the pre-bump epoch, so its post-network guard
        // fails and it won't persist rotated tokens into the stores
        // we just emptied.
        sessionEpoch += 1

        // No credentials on file — nothing to revoke.
        guard let dpopHandle, let refreshToken, !refreshToken.isEmpty else {
            if let wipeError {
                throw wipeError
            }
            return
        }

        // Sign /revoke inline from the snapshot. The standard
        // ``DPoPInterceptor`` would provision a fresh keypair
        // against the now-empty keystore, whose fingerprint
        // wouldn't match the session's pinned one server-side.
        var request = buildRequest(path: "revoke")
        request.setValue(refreshToken, forHTTPHeaderField: HTTPHeader.refreshToken)

        guard let htu = DPoPInterceptor.htuURL(for: request) else {
            throw PreludeAuthError.invalidConfiguration("URLRequest is missing a URL")
        }

        // A signing failure returns instead of throwing (unless the
        // wipe itself failed): the wipe already landed, so the user is
        // logged out locally and the server session TTLs out. Send
        // errors below still surface so callers can retry.
        let proof: String
        do {
            proof = try DefaultDPoPProofBuilder().create(
                key: dpopHandle,
                method: request.httpMethod ?? "POST",
                url: htu,
                nonce: dpopNonce,
                jti: nil,
                now: Date(),
                clockSkewSec: dpopSkewSec
            )
        } catch {
            if let wipeError {
                throw wipeError
            }
            return
        }
        request.setValue(proof, forHTTPHeaderField: HTTPHeader.dpop)

        // If /revoke also throws, surface the wipe error in
        // preference: the local credential left behind on the
        // device is more security-critical than an unrevoked
        // server session, which TTLs out on its own.
        do {
            try await httpClient.sendExpectingNoBody(request)
        } catch {
            if let wipeError {
                throw wipeError
            }
            throw error
        }

        if let wipeError {
            throw wipeError
        }
    }

    /// Delete every domain-scoped credential. Best-effort — every
    /// delete is attempted regardless of earlier failures, then the
    /// first captured error is rethrown.
    func clearAllStores() async throws {
        var firstError: Error?

        func attempt(_ body: () throws -> Void) {
            do { try body() } catch {
                if firstError == nil {
                    firstError = error
                }
            }
        }

        // Inline the cache wipe rather than threading async into
        // `attempt`: the actor cache is the only async store, and
        // its failure mode is identical to the synchronous ones.
        attempt { try keyStore.delete(domain: domain) }
        attempt { try keyStore.deleteNonce(domain: domain) }
        attempt { try keyStore.deleteClockSkew(domain: domain) }
        attempt { try refreshTokenStore.delete(domain: domain) }

        // Server-set cookies (e.g. `did`,
        // `__Host-verification-login_<id>`) live in
        // `HTTPCookieStorage.shared` and survive across launches.
        // Wipe everything scoped to our host so a logout doesn't
        // leave bearer-adjacent material behind.
        for cookie in HTTPCookieStorage.shared.cookies(for: baseURL) ?? [] {
            HTTPCookieStorage.shared.deleteCookie(cookie)
        }

        do {
            try await accessTokenCache.clear(domain: domain)
        } catch {
            if firstError == nil {
                firstError = error
            }
        }
        // In-memory step-up handle. Logically part of the wipe — a
        // stale challenge that survives logout would let an
        // observer believe a flow is still in progress.
        activeStepUp = nil
        sealed = false

        if let firstError {
            throw firstError
        }
    }
}
