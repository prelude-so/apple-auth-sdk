import Foundation
import Security

/// DPoP key store backed by the software Keychain — used on the
/// Simulator and on the rare device without a Secure Enclave. Keys
/// are encrypted at rest but lack the enclave's hardware extraction
/// guarantee.
struct SoftwareDPoPKeyStore: DPoPKeyStore {
    let backend: KeychainBackend
    let nonceStore: DPoPNonceStore
    let clockSkewStore: DPoPClockSkewStore

    /// Serialises ``getOrCreate(domain:)`` so concurrent first-time
    /// callers don't both reach `create`. Per-instance: in
    /// production each ``PreludeAuthClient`` owns one store, so
    /// in-process callers naturally share this lock.
    private let creationLock = NSLock()

    init(backend: KeychainBackend = DefaultKeychainBackend()) {
        self.backend = backend
        nonceStore = DPoPNonceStore(backend: backend)
        clockSkewStore = DPoPClockSkewStore(backend: backend)
    }

    func create(domain: String) throws -> DPoPKey {
        let tag = DPoPKeychainOps.applicationTag(for: domain)
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            ],
        ]

        let privateKey = try backend.createRandomKey(attributes)
        let publicKey = try DPoPKeychainOps.derivePublicKey(from: privateKey)
        return DPoPKeyHandle(domain: domain, privateKey: privateKey, publicKey: publicKey)
    }

    func getOrCreate(domain: String) throws -> DPoPKey {
        try readOrCreateUnderLock(creationLock, domain: domain)
    }
}
