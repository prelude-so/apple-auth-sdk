import Foundation
import Security

/// Per-domain stable device identifier persisted in the Keychain.
/// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` deliberately keeps
/// it off iCloud sync and out of backups, so a restored device gets a
/// fresh id — the intended per-install identity.
struct DeviceIDStore {
    private static let service = "so.prelude.auth.device_id"

    private let keychain: KeychainBackend
    private let creationLock = NSLock()
    private let cache = Cache()

    init(keychain: KeychainBackend = DefaultKeychainBackend()) {
        self.keychain = keychain
    }

    /// Return the persisted id for `domain`, creating one on first use.
    /// The lock covers this store instance only; another instance or
    /// another process can still race the write, which the
    /// `errSecDuplicateItem` path recovers from.
    func getOrCreate(domain: String) throws -> String {
        if let cached = cache.get(domain) {
            return cached
        }

        creationLock.lock()
        defer { creationLock.unlock() }

        if let cached = cache.get(domain) {
            return cached
        }
        if let persisted = try readKeychain(domain: domain) {
            cache.set(domain, persisted)
            return persisted
        }

        let value = UUID().uuidString.lowercased()
        let attrs: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: domain,
            kSecValueData as String: Data(value.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let status = keychain.add(attrs)
        if status == errSecSuccess {
            cache.set(domain, value)
            return value
        }
        if status == errSecDuplicateItem {
            // A peer wrote between our read and `add`; re-read so all
            // callers converge on the persisted id. Surface the
            // re-read's error rather than masking it as duplicate-item.
            if let racing = try readKeychain(domain: domain) {
                cache.set(domain, racing)
                return racing
            }
        }
        throw SessionTokenStoreError.keychainFailure(status)
    }

    private func readKeychain(domain: String) throws -> String? {
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
        } catch let DPoPKeyStoreError.keychainFailure(status) {
            throw SessionTokenStoreError.keychainFailure(status)
        } catch {
            throw SessionTokenStoreError.keychainFailure(errSecDecode)
        }
        guard let item else { return nil }
        guard let data = item as? Data, let value = String(data: data, encoding: .utf8) else {
            throw SessionTokenStoreError.keychainFailure(errSecDecode)
        }
        return value
    }
}

/// Reference-typed scratch space so the value-typed
/// ``DeviceIDStore`` can carry mutable cache state across copies.
/// Fronts the Keychain so steady-state requests skip the `SecItem`
/// XPC round-trip.
private final class Cache: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: String] = [:]

    func get(_ domain: String) -> String? {
        lock.lock(); defer { lock.unlock() }
        return values[domain]
    }

    func set(_ domain: String, _ value: String) {
        lock.lock(); defer { lock.unlock() }
        values[domain] = value
    }
}
