import Foundation
import Security

enum SessionTokenStoreError: Error {
    case keychainFailure(OSStatus)
    /// Persisted value couldn't be encoded/decoded.
    case codecFailure
}

struct AccessTokenEntry: Codable, Equatable {
    var accessToken: String
    /// Seconds since the Unix epoch, already adjusted for observed
    /// client/server clock skew at cache time.
    var expiresAt: Int
}

/// Defense in depth: every textual representation drops the bearer
/// access token. `expiresAt` is fine to surface — useful for
/// debugging, no security value.
extension AccessTokenEntry: CustomStringConvertible {
    var description: String {
        "AccessTokenEntry(accessToken: <redacted>, expiresAt: \(expiresAt))"
    }
}

extension AccessTokenEntry: CustomDebugStringConvertible {
    var debugDescription: String {
        description
    }
}

extension AccessTokenEntry: CustomReflectable {
    var customMirror: Mirror {
        Mirror(
            self,
            children: [
                "accessToken": "<redacted>",
                "expiresAt": expiresAt,
            ],
            displayStyle: .struct
        )
    }
}

/// In-memory cache of access tokens per Prelude domain, mirrored to
/// the Keychain so a cold start can render the profile and skip a
/// refresh round-trip when the token is still valid. ``set``,
/// ``invalidate``, and ``clear`` write the Keychain before memory,
/// so memory and disk never disagree.
actor AccessTokenCache {
    private static let service = "so.prelude.auth.access"

    private let clock: NowProvider
    private let keychain: KeychainBackend
    private var memory: [String: AccessTokenEntry] = [:]

    init(
        clock: @escaping NowProvider = defaultNowProvider,
        keychain: KeychainBackend = DefaultKeychainBackend()
    ) {
        self.clock = clock
        self.keychain = keychain
    }

    /// Populate memory from the Keychain. Best-effort; any failure
    /// leaves the cache empty. Call once per domain at client init.
    func hydrate(domain: String) {
        if let entry = try? readKeychain(domain: domain) {
            memory[domain] = entry
        }
    }

    /// Cached entry, or `nil` if none or expired. Strict `<`:
    /// equality is still valid.
    func get(domain: String) -> AccessTokenEntry? {
        guard let entry = memory[domain] else { return nil }
        return entry.expiresAt < Int(clock().timeIntervalSince1970) ? nil : entry
    }

    /// Cached entry regardless of expiration. Profile readers use
    /// this so the app can render the logged-in user while a
    /// refresh is in flight.
    func getWithoutExpirationCheck(domain: String) -> AccessTokenEntry? {
        memory[domain]
    }

    /// Persist a new entry. Keychain write before in-memory update —
    /// a failing mirror leaves both sides pre-call.
    func set(domain: String, entry: AccessTokenEntry) throws {
        try writeKeychain(domain: domain, entry: entry)
        memory[domain] = entry
    }

    /// Mark the entry expired without removing it. The entry stays
    /// retrievable via ``getWithoutExpirationCheck(domain:)``. Keychain
    /// first: if the write fails, downgrading memory alone would let a
    /// cold start rehydrate the still-valid persisted entry.
    func invalidate(domain: String) throws {
        guard let current = memory[domain] else { return }
        var invalidated = current
        invalidated.expiresAt = Int(clock().timeIntervalSince1970) - 1
        try writeKeychain(domain: domain, entry: invalidated)
        memory[domain] = invalidated
    }

    /// Drop the in-memory entry, leaving the Keychain copy intact.
    func evict(domain: String) {
        memory.removeValue(forKey: domain)
    }

    /// Remove the entry from both memory and the Keychain. Keychain
    /// first: clearing memory alone would let a cold start resurrect it.
    func clear(domain: String) throws {
        try deleteKeychain(domain: domain)
        memory.removeValue(forKey: domain)
    }

    // MARK: - Keychain helpers

    private static func toSessionError(_ error: Error) -> SessionTokenStoreError {
        if let keyStoreError = error as? DPoPKeyStoreError,
           case let .keychainFailure(status) = keyStoreError {
            return .keychainFailure(status)
        }
        return .keychainFailure(errSecDecode)
    }

    private func readKeychain(domain: String) throws -> AccessTokenEntry? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: domain,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        let item: CFTypeRef?
        do {
            item = try keychain.copyMatching(query)
        } catch {
            throw Self.toSessionError(error)
        }
        guard let item else { return nil }
        guard let data = item as? Data else {
            throw SessionTokenStoreError.keychainFailure(errSecDecode)
        }
        return try? JSONDecoder().decode(AccessTokenEntry.self, from: data)
    }

    private func writeKeychain(domain: String, entry: AccessTokenEntry) throws {
        let data: Data
        do {
            data = try JSONEncoder().encode(entry)
        } catch {
            throw SessionTokenStoreError.codecFailure
        }

        let matchQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: domain,
        ]
        let update: [String: Any] = [kSecValueData as String: data]

        let updateStatus = keychain.update(matchQuery, attributesToUpdate: update)
        if updateStatus == errSecSuccess {
            return
        }
        if updateStatus != errSecItemNotFound {
            throw SessionTokenStoreError.keychainFailure(updateStatus)
        }

        var addAttrs = matchQuery
        addAttrs[kSecValueData as String] = data
        addAttrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = keychain.add(addAttrs)
        guard addStatus == errSecSuccess else {
            throw SessionTokenStoreError.keychainFailure(addStatus)
        }
    }

    private func deleteKeychain(domain: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: domain,
        ]
        let status = keychain.delete(query)
        if status != errSecSuccess, status != errSecItemNotFound {
            throw SessionTokenStoreError.keychainFailure(status)
        }
    }
}
