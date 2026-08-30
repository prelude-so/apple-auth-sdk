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
        // Snapshot what /revoke needs before wiping the stores so
        // the request can still be DPoP-signed afterwards.
        //
        // `try?` on the reads is load-bearing: a corrupted Keychain
        // item can fail `get` but still succeed `delete`, so the
        // wipe must run regardless. Losing a snapshot just means
        // we can't sign /revoke; leaving the user stuck logged-in
        // is worse than an unrevoked server session.
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

        // Order is **snapshot → wipe → bump → /revoke**. Bumping
        // AFTER the wipe is load-bearing for the resurrection
        // guard: any refresh whose snapshot read pre-wipe tokens
        // captured the pre-bump epoch, so its post-network check
        // sees the mismatch and bails before persisting rotated
        // tokens back into stores we just emptied. A refresh that
        // starts after the wipe reads an empty store and is
        // rejected by the server.
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

        // Sign /revoke from the snapshot. A signing failure here
        // (e.g. `errSecAuthFailed` because the Secure Enclave key
        // was invalidated by a biometric reset) silently degrades:
        // the local wipe already landed, so the user is logged
        // out from the device's point of view. Forcing the caller
        // to handle a thrown signing error in addition to a clean
        // logout return would be worse than skipping the server-
        // side revocation, which TTLs out on its own. Network /
        // HTTP errors during the send below continue to surface
        // so callers can retry.
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

        if let firstError {
            throw firstError
        }
    }
}
