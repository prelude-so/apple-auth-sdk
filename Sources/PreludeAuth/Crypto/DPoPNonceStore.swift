import Foundation
import Security

/// Keychain-backed DPoP nonce storage, owned per ``DPoPKeyStore``.
/// ``set`` is a non-atomic upsert (`SecItemUpdate` then `SecItemAdd`) and
/// the lock is per-instance, so a racing writer can lose the add with
/// `errSecDuplicateItem`; the fallback path then overwrites.
struct DPoPNonceStore {
    private let backend: KeychainBackend
    private let service: String
    private let lock = NSLock()

    init(backend: KeychainBackend, service: String = "so.prelude.auth.dpop-nonce") {
        self.backend = backend
        self.service = service
    }

    func get(domain: String) throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: domain,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        guard let item = try backend.copyMatching(query) else { return nil }
        guard let data = item as? Data else {
            throw DPoPKeyStoreError.keychainFailure(errSecDecode)
        }
        return String(data: data, encoding: .utf8)
    }

    func set(domain: String, nonce: String) throws {
        guard let data = nonce.data(using: .utf8) else { return }

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

        // Cross-process race: another writer won the add. Overwrite.
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
