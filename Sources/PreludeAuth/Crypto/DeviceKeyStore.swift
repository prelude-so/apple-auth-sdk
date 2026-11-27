import Foundation
import Security

/// Reported to the server as a hint only.
enum DeviceKeyStorage: String {
    case secureEnclave = "secure_enclave"
    case software
}

/// One key per app install. Logout keeps it, and `ThisDeviceOnly` keeps it
/// out of backups and off other phones.
struct DeviceKeyStore {
    /// Per app, not per domain: a domain change must not rotate the ID, and
    /// apps in one Keychain access group must not share a key.
    static let applicationTag = Data("so.prelude.auth.device.\(Bundle.main.bundleIdentifier ?? "app")".utf8)

    let backend: KeychainBackend
    let storage: DeviceKeyStorage

    /// Shared across instances so two clients in one process create one key.
    private static let creationLock = NSLock()

    init(backend: KeychainBackend = DefaultKeychainBackend(), storage: DeviceKeyStorage) {
        self.backend = backend
        self.storage = storage
    }

    static func makeDefault() -> Self {
        Self(storage: DPoPKeyStoreFactory.isSecureEnclaveAvailable ? .secureEnclave : .software)
    }

    /// A read error is thrown, never treated as "no key": a new key would change the ID.
    func getOrCreate() throws -> DPoPKey {
        Self.creationLock.lock()
        defer { Self.creationLock.unlock() }

        if let existing = try get() {
            return existing
        }
        do {
            return try create()
        } catch {
            if let racingWinner = try? get() {
                return racingWinner
            }
            throw error
        }
    }

    func get() throws -> DPoPKey? {
        guard let privateKey = try DPoPKeychainOps.findPrivateKey(tag: Self.applicationTag, backend: backend) else {
            return nil
        }
        let publicKey = try DPoPKeychainOps.derivePublicKey(from: privateKey)
        return DPoPKeyHandle(domain: "", privateKey: privateKey, publicKey: publicKey)
    }

    func delete() throws {
        Self.creationLock.lock()
        defer { Self.creationLock.unlock() }
        try DPoPKeychainOps.deletePrivateKey(tag: Self.applicationTag, backend: backend)
    }

    private func create() throws -> DPoPKey {
        var privateAttrs: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: Self.applicationTag,
        ]
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
        ]

        switch storage {
        case .secureEnclave:
            // No user-presence flag: a passcode or biometry change must
            // not invalidate the key.
            var acError: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                .privateKeyUsage,
                &acError
            ) else {
                throw DPoPKeyStoreError.keyGenerationFailed(underlying: acError?.takeRetainedValue())
            }
            privateAttrs[kSecAttrAccessControl as String] = access
            attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        case .software:
            privateAttrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        }
        attributes[kSecPrivateKeyAttrs as String] = privateAttrs

        let privateKey = try backend.createRandomKey(attributes)
        let publicKey = try DPoPKeychainOps.derivePublicKey(from: privateKey)
        return DPoPKeyHandle(domain: "", privateKey: privateKey, publicKey: publicKey)
    }
}
