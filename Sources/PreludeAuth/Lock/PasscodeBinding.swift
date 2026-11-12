import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// How the passcode is tied to its Keychain item.
protocol PasscodeBinding: Sendable {
    /// Attributes of an item that only `passcode` opens.
    func seal(_ passcode: String) throws -> [String: Any]

    /// Whether `passcode` opens the item that `query` finds.
    func opens(_ query: [String: Any], with passcode: String, in keychain: KeychainBackend) throws -> Bool
}

enum PasscodeBindingFactory {
    /// The Simulator has no application passwords, so it gets the
    /// digest. The choice is made at compile time: a device never
    /// falls back to it.
    static func makeDefault() -> PasscodeBinding {
        #if targetEnvironment(simulator)
            SaltedDigestBinding()
        #else
            ApplicationPasswordBinding()
        #endif
    }
}

/// The passcode is the item's application password: it is never
/// stored, and a successful read is the verification.
struct ApplicationPasswordBinding: PasscodeBinding {
    func seal(_ passcode: String) throws -> [String: Any] {
        guard let access = AppLockStore.accessControl(.applicationPassword) else {
            throw PreludeAuthError.lockUnavailable("Cannot create the passcode's access control")
        }
        return try [
            kSecValueData as String: AppLockStore.randomBytes(),
            kSecAttrAccessControl as String: access,
            kSecUseAuthenticationContext as String: Self.context(passcode: passcode),
        ]
    }

    func opens(_ query: [String: Any], with passcode: String, in keychain: KeychainBackend) throws -> Bool {
        var lookup = query
        lookup[kSecUseAuthenticationContext as String] = try Self.context(passcode: passcode)

        // A wrong application password is a failed decryption or,
        // with interaction off, a refused prompt.
        do {
            return try keychain.copyMatching(lookup) != nil
        } catch DPoPKeyStoreError.keychainFailure(errSecAuthFailed),
            DPoPKeyStoreError.keychainFailure(errSecInteractionNotAllowed) {
            return false
        }
    }

    /// Pure decryption; no system sheet.
    private static func context(passcode: String) throws -> LAContext {
        let context = LAContext()
        guard context.setCredential(Data(passcode.utf8), type: .applicationPassword) else {
            throw PreludeAuthError.lockUnavailable("This device cannot bind an application password")
        }
        context.interactionNotAllowed = true
        return context
    }
}

/// The item holds a salt and the digest of salt + passcode. Weaker
/// than an application password: anything that reads the item can
/// guess a short passcode offline.
struct SaltedDigestBinding: PasscodeBinding {
    func seal(_ passcode: String) throws -> [String: Any] {
        let salt = AppLockStore.randomBytes()
        return [
            kSecValueData as String: salt + Self.digest(passcode, salt: salt),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
    }

    func opens(_ query: [String: Any], with passcode: String, in keychain: KeychainBackend) throws -> Bool {
        guard let sealed = try keychain.copyMatching(query) as? Data, sealed.count > SHA256.byteCount else {
            throw PreludeAuthError.lockUnavailable("Cannot decode the passcode item")
        }
        let salt = sealed.dropLast(SHA256.byteCount)
        return Self.digest(passcode, salt: salt) == sealed.suffix(SHA256.byteCount)
    }

    private static func digest(_ passcode: String, salt: Data) -> Data {
        Data(SHA256.hash(data: salt + Data(passcode.utf8)))
    }
}
