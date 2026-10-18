import Foundation
import LocalAuthentication
import Security

/// App-lock credentials: a passcode and an optional biometric
/// shortcut. The passcode is never stored; it is the application
/// password of a Keychain item, so a successful read is the
/// verification. Attempts are counted here because a short
/// passcode has no hardware rate limit.
struct AppLockStore {
    static let defaultMaxAttempts = 5

    private static let passcodeService = "so.prelude.auth.lock.passcode"
    private static let biometricService = "so.prelude.auth.lock.biometric"
    private static let attemptService = "so.prelude.auth.lock.attempts"

    let domain: String
    let maxAttempts: Int
    private let keychain: KeychainBackend

    init(
        domain: String,
        maxAttempts: Int = Self.defaultMaxAttempts,
        keychain: KeychainBackend = DefaultKeychainBackend()
    ) {
        self.domain = domain
        self.maxAttempts = maxAttempts
        self.keychain = keychain
    }

    // MARK: - Passcode

    var hasPasscode: Bool {
        exists(service: Self.passcodeService)
    }

    /// Also drops the biometric shortcut, armed against the old one.
    func setPasscode(_ passcode: String) throws {
        guard passcode.count >= 4 else {
            throw PreludeAuthError.invalidPasscode("A passcode needs at least 4 digits")
        }
        guard let access = Self.accessControl(.applicationPassword) else {
            throw PreludeAuthError.lockUnavailable("Cannot create the passcode's access control")
        }

        var attributes = query(service: Self.passcodeService)
        attributes[kSecValueData as String] = Self.randomBytes()
        attributes[kSecAttrAccessControl as String] = access
        attributes[kSecUseAuthenticationContext as String] = try Self.context(passcode: passcode)

        // Fallible prep is done; only now replace the old credentials.
        _ = keychain.delete(query(service: Self.passcodeService))
        disableBiometrics()

        let status = keychain.add(attributes)
        guard status == errSecSuccess else {
            throw PreludeAuthError.lockUnavailable("Cannot store the passcode (OSStatus \(status))")
        }
        resetAttempts()
    }

    /// Throws `invalidPasscode` on a wrong one and `lockedOut` once
    /// the attempts are spent.
    func verify(passcode: String) throws {
        guard hasPasscode else {
            throw PreludeAuthError.lockUnavailable("No passcode is set")
        }
        let spent = try attempts()
        guard spent < maxAttempts else {
            throw PreludeAuthError.lockedOut("Too many attempts")
        }

        var lookup = query(service: Self.passcodeService)
        lookup[kSecReturnData as String] = true
        lookup[kSecMatchLimit as String] = kSecMatchLimitOne
        lookup[kSecUseAuthenticationContext as String] = try Self.context(passcode: passcode)

        // A wrong application password is a failed decryption or,
        // with interaction off, a refused prompt.
        let read: CFTypeRef?
        do {
            read = try keychain.copyMatching(lookup)
        } catch DPoPKeyStoreError.keychainFailure(errSecAuthFailed),
            DPoPKeyStoreError.keychainFailure(errSecInteractionNotAllowed) {
            read = nil
        } catch {
            throw PreludeAuthError.lockUnavailable("Cannot read the passcode item: \(error)")
        }

        guard read != nil else {
            try setAttempts(spent + 1)
            if spent + 1 >= maxAttempts {
                throw PreludeAuthError.lockedOut("Too many attempts")
            }
            throw PreludeAuthError.invalidPasscode(
                "Wrong passcode — \(maxAttempts - spent - 1) attempts left"
            )
        }
        resetAttempts()
    }

    // MARK: - Biometric shortcut

    var isBiometricsEnabled: Bool {
        exists(service: Self.biometricService)
    }

    var isBiometricsAvailable: Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    /// Requires a passcode, so there is always a way in.
    func enableBiometrics() throws {
        guard hasPasscode else {
            throw PreludeAuthError.lockUnavailable("Set a passcode before enabling biometrics")
        }
        guard isBiometricsAvailable else {
            throw PreludeAuthError.lockUnavailable("This device has no enrolled biometrics")
        }
        guard let access = Self.accessControl(.biometryCurrentSet) else {
            throw PreludeAuthError.lockUnavailable("Cannot create the biometric access control")
        }

        _ = keychain.delete(query(service: Self.biometricService))
        var attributes = query(service: Self.biometricService)
        attributes[kSecValueData as String] = Self.randomBytes()
        attributes[kSecAttrAccessControl as String] = access

        let status = keychain.add(attributes)
        guard status == errSecSuccess else {
            throw PreludeAuthError.lockUnavailable("Cannot store the biometric key (OSStatus \(status))")
        }
    }

    func disableBiometrics() {
        _ = keychain.delete(query(service: Self.biometricService))
    }

    /// Blocks while the system sheet is up; keep off the main actor.
    func verifyBiometrics(reason: String) throws {
        guard isBiometricsEnabled else {
            throw PreludeAuthError.lockUnavailable("The biometric shortcut is not enabled")
        }
        let context = LAContext()
        context.localizedReason = reason

        var lookup = query(service: Self.biometricService)
        lookup[kSecReturnData as String] = true
        lookup[kSecMatchLimit as String] = kSecMatchLimitOne
        lookup[kSecUseAuthenticationContext as String] = context

        guard let read = try? keychain.copyMatching(lookup), read != nil else {
            throw PreludeAuthError.lockUnavailable("Biometric check was not confirmed")
        }
        resetAttempts()
    }

    // MARK: - Wipe

    func clear() {
        _ = keychain.delete(query(service: Self.passcodeService))
        _ = keychain.delete(query(service: Self.biometricService))
        resetAttempts()
    }

    // MARK: - Attempts

    /// Fails closed: an unreadable counter refuses the passcode.
    private func attempts() throws -> Int {
        var lookup = query(service: Self.attemptService)
        lookup[kSecReturnData as String] = true
        lookup[kSecMatchLimit as String] = kSecMatchLimitOne
        guard let item = try keychain.copyMatching(lookup) else {
            return 0
        }
        guard let data = item as? Data,
              let text = String(bytes: data, encoding: .utf8),
              let value = Int(text)
        else {
            throw PreludeAuthError.lockUnavailable("Cannot decode the attempt counter")
        }
        return value
    }

    private func setAttempts(_ value: Int) throws {
        let data = Data(String(value).utf8)
        var attributes = query(service: Self.attemptService)
        if keychain.update(attributes, attributesToUpdate: [kSecValueData as String: data]) == errSecSuccess {
            return
        }
        attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = keychain.add(attributes)
        guard status == errSecSuccess else {
            throw PreludeAuthError.lockUnavailable("Cannot record the attempt (OSStatus \(status))")
        }
    }

    private func resetAttempts() {
        _ = keychain.delete(query(service: Self.attemptService))
    }

    // MARK: - Keychain helpers

    private func query(service: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: domain,
        ]
    }

    /// Attributes sit outside the access control, so this needs
    /// no passcode or prompt.
    private func exists(service: String) -> Bool {
        var lookup = query(service: service)
        lookup[kSecReturnAttributes as String] = true
        lookup[kSecMatchLimit as String] = kSecMatchLimitOne
        lookup[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail
        do {
            return try keychain.copyMatching(lookup) != nil
        } catch let error as DPoPKeyStoreError {
            guard case let .keychainFailure(status) = error else {
                return false
            }
            return status == errSecInteractionNotAllowed
        } catch {
            return false
        }
    }

    private static func accessControl(_ flags: SecAccessControlCreateFlags) -> SecAccessControl? {
        SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            nil
        )
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

    private static func randomBytes() -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        if SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) != errSecSuccess {
            bytes = (0 ..< 32).map { _ in UInt8.random(in: .min ... .max) }
        }
        return Data(bytes)
    }
}
