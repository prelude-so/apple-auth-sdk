import Foundation
import Security

/// Keychain-backed per-domain DPoP clock-skew storage. Mirrors
/// ``DPoPNonceStore`` so the persistence story is uniform — both
/// values are recovered from a single backend on cold start.
///
/// Skew is `serverTime - localTime` in seconds (TimeInterval, to
/// line up with the rest of the codebase). Sub-second precision is
/// preserved on the way in and out so the retry threshold stays
/// honest.
///
/// Write atomicity, locking, and the cross-process duplicate-item
/// fallback follow ``DPoPNonceStore`` exactly.
struct DPoPClockSkewStore {
    private let backend: KeychainBackend
    private let service: String
    private let lock = NSLock()

    init(backend: KeychainBackend, service: String = "so.prelude.auth.dpop-clock-skew") {
        self.backend = backend
        self.service = service
    }

    func get(domain: String) throws -> TimeInterval? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: domain,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        guard let item = try backend.copyMatching(query) else { return nil }
        guard let data = item as? Data,
              let text = String(data: data, encoding: .utf8),
              let value = TimeInterval(text) else {
            // Treat malformed values as "no skew" — a stale write
            // from a future SDK shouldn't crash callers.
            return nil
        }
        return value
    }

    func set(domain: String, skew: TimeInterval) throws {
        guard let data = String(skew).data(using: .utf8) else { return }

        lock.lock()
        defer { lock.unlock() }

        let matchQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: domain,
        ]
        let update: [String: Any] = [kSecValueData as String: data]

        let updateStatus = backend.update(matchQuery, attributesToUpdate: update)
        if updateStatus == errSecSuccess {
            return
        }
        if updateStatus != errSecItemNotFound {
            throw DPoPKeyStoreError.keychainFailure(updateStatus)
        }

        var addAttrs = matchQuery
        addAttrs[kSecValueData as String] = data
        addAttrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = backend.add(addAttrs)
        if addStatus == errSecSuccess {
            return
        }
        if addStatus != errSecDuplicateItem {
            throw DPoPKeyStoreError.keychainFailure(addStatus)
        }

        let retryStatus = backend.update(matchQuery, attributesToUpdate: update)
        if retryStatus != errSecSuccess {
            throw DPoPKeyStoreError.keychainFailure(retryStatus)
        }
    }

    func delete(domain: String) throws {
        lock.lock()
        defer { lock.unlock() }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: domain,
        ]
        let status = backend.delete(query)
        if status != errSecSuccess, status != errSecItemNotFound {
            throw DPoPKeyStoreError.keychainFailure(status)
        }
    }
}
