import Foundation
import Security

/// DPoP key store backed by the Secure Enclave. Key material stays
/// inside the enclave; the returned `SecKey` is a proxy handle.
struct SecureEnclaveDPoPKeyStore: DPoPKeyStore {
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
        var acError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            .privateKeyUsage,
            &acError
        ) else {
            throw DPoPKeyStoreError.keyGenerationFailed(
                underlying: acError?.takeRetainedValue()
            )
        }

        let tag = DPoPKeychainOps.applicationTag(for: domain)
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access,
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
