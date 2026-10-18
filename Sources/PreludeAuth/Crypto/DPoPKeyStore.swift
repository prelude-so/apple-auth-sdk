import Foundation
import Security

enum DPoPKeyStoreError: Error {
    case keyGenerationFailed(underlying: Error?)
    case publicKeyDerivationFailed
    case keychainFailure(OSStatus)
}

// MARK: - Protocol

/// Persistent DPoP keypair + nonce + clock-skew storage, scoped by
/// Prelude domain. `getOrCreate` is a per-conformer requirement rather
/// than a default extension so that each store can hold its creation
/// lock as a private stored property.
protocol DPoPKeyStore: Sendable {
    var backend: KeychainBackend { get }
    var nonceStore: DPoPNonceStore { get }
    var clockSkewStore: DPoPClockSkewStore { get }

    func create(domain: String) throws -> DPoPKey
    func get(domain: String) throws -> DPoPKey?
    func getOrCreate(domain: String) throws -> DPoPKey
    func delete(domain: String) throws
    func getNonce(domain: String) throws -> String?
    func setNonce(domain: String, nonce: String) throws
    func deleteNonce(domain: String) throws
    func getClockSkew(domain: String) throws -> TimeInterval?
    func setClockSkew(domain: String, skew: TimeInterval) throws
    func deleteClockSkew(domain: String) throws
}

extension DPoPKeyStore {
    func get(domain: String) throws -> DPoPKey? {
        let tag = DPoPKeychainOps.applicationTag(for: domain)
        guard let privateKey = try DPoPKeychainOps.findPrivateKey(tag: tag, backend: backend) else {
            return nil
        }
        let publicKey = try DPoPKeychainOps.derivePublicKey(from: privateKey)
        return DPoPKeyHandle(domain: domain, privateKey: privateKey, publicKey: publicKey)
    }

    /// Shared `getOrCreate` body; the caller passes in its own lock, which
    /// stays a private stored property. On a `create` failure, re-read: a
    /// racing writer in another instance or process may already have
    /// committed this domain's key, and callers rely on converging on one.
    func readOrCreateUnderLock(_ lock: NSLock, domain: String) throws -> DPoPKey {
        lock.lock()
        defer { lock.unlock() }

        if let existing = try get(domain: domain) {
            return existing
        }

        do {
            return try create(domain: domain)
        } catch {
            if let racingWinner = try? get(domain: domain) {
                return racingWinner
            }
            throw error
        }
    }

    func delete(domain: String) throws {
        let tag = DPoPKeychainOps.applicationTag(for: domain)
        try DPoPKeychainOps.deletePrivateKey(tag: tag, backend: backend)
    }

    func getNonce(domain: String) throws -> String? {
        try nonceStore.get(domain: domain)
    }

    func setNonce(domain: String, nonce: String) throws {
        try nonceStore.set(domain: domain, nonce: nonce)
    }

    func deleteNonce(domain: String) throws {
        try nonceStore.delete(domain: domain)
    }

    func getClockSkew(domain: String) throws -> TimeInterval? {
        try clockSkewStore.get(domain: domain)
    }

    func setClockSkew(domain: String, skew: TimeInterval) throws {
        try clockSkewStore.set(domain: domain, skew: skew)
    }

    func deleteClockSkew(domain: String) throws {
        try clockSkewStore.delete(domain: domain)
    }
}

// MARK: - Factory

/// Picks a ``DPoPKeyStore`` for the current device. Secure Enclave
/// availability is probed once and cached for process lifetime;
/// `nonisolated(unsafe)` is safe because that cached `Bool` is written
/// exactly once on first access and only read afterwards.
enum DPoPKeyStoreFactory {
    static func makeDefault() -> DPoPKeyStore {
        isSecureEnclaveAvailable ? SecureEnclaveDPoPKeyStore() : SoftwareDPoPKeyStore()
    }

    // swiftformat:disable:next modifierOrder
    nonisolated(unsafe) private static let isSecureEnclaveAvailable: Bool = probeSecureEnclave()

    private static func probeSecureEnclave() -> Bool {
        var acError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            .privateKeyUsage,
            &acError
        ) else {
            _ = acError?.takeRetainedValue()
            return false
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false,
                kSecAttrAccessControl as String: access,
            ],
        ]

        var genError: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes as CFDictionary, &genError) != nil else {
            _ = genError?.takeRetainedValue()
            return false
        }
        return true
    }
}

// MARK: - Shared helpers

enum DPoPKeychainOps {
    static func applicationTag(for domain: String) -> Data {
        Data("so.prelude.auth.dpop.\(domain)".utf8)
    }

    static func findPrivateKey(tag: Data, backend: KeychainBackend) throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        guard let item = try backend.copyMatching(query) else { return nil }
        // Force-cast safe: kSecReturnRef + kSecClassKey always yields a SecKey.
        return (item as! SecKey) // swiftlint:disable:this force_cast
    }

    static func deletePrivateKey(tag: Data, backend: KeychainBackend) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        ]
        let status = backend.delete(query)
        if status != errSecSuccess, status != errSecItemNotFound {
            throw DPoPKeyStoreError.keychainFailure(status)
        }
    }

    static func derivePublicKey(from privateKey: SecKey) throws -> SecKey {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw DPoPKeyStoreError.publicKeyDerivationFailed
        }
        return publicKey
    }
}
