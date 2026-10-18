import Foundation

// MARK: - Public facade

extension PreludeAuthClient {
    public var isSealed: Bool {
        get async { await impl.isSealed }
    }

    /// Hide the profile and token and drop the token from memory.
    /// The Keychain copy stays, so ``unseal()`` needs no network.
    /// Returns `false` when there is no session to seal.
    @discardableResult
    public func seal() async -> Bool {
        await impl.seal()
    }

    /// Restore the token from the Keychain. Authenticates nothing;
    /// ``PreludeIdleLock`` proves presence first.
    public func unseal() async {
        await impl.unseal()
    }
}

// MARK: - Implementation

extension PreludeAuthClient.Impl {
    var isSealed: Bool {
        sealed
    }

    @discardableResult
    func seal() async -> Bool {
        guard hasSession else {
            return false
        }
        sealed = true
        // An in-flight refresh would repopulate memory after the evict.
        await drainInflightRefresh()
        await accessTokenCache.evict(domain: domain)
        return true
    }

    func unseal() async {
        await accessTokenCache.hydrate(domain: domain)
        sealed = false
    }

    func requireUnsealed() throws {
        if sealed {
            throw PreludeAuthError.sessionLocked("Unlock the session before making protected calls")
        }
    }

    private var hasSession: Bool {
        let token = try? refreshTokenStore.get(domain: domain)?.refreshToken
        return !(token ?? "").isEmpty
    }
}
