import Foundation

// MARK: - Public facade

extension PreludeAuthClient {
    /// Delete the device key of this app install. The next sign-in creates
    /// a new key, with a new `device_key_id`. ``logout()`` keeps the key.
    /// A step-up on a session signed in with the old key fails until the
    /// user signs in again.
    public func resetDeviceKey() async throws {
        try await impl.resetDeviceKey()
    }
}

// MARK: - Implementation

extension PreludeAuthClient.Impl {
    func resetDeviceKey() throws {
        try deviceKeyStore.delete()
    }
}
