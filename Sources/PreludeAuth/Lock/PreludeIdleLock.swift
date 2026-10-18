#if canImport(UIKit)

    import Combine
    import Foundation
    import UIKit

    /// Seals a ``PreludeAuthClient`` after `threshold` seconds in the
    /// background and lifts the seal once presence is proven.
    ///
    /// `.inactive` is ignored: the Face ID sheet makes the app
    /// inactive, so sealing on it would re-lock during unlock.
    /// Calling ``PreludeAuthClient/seal()`` directly bypasses
    /// ``isLocked``.
    public final class PreludeIdleLock: ObservableObject, @unchecked Sendable {
        public static let defaultMaxAttempts = 5

        @Published public private(set) var isLocked = false

        /// Whether a passcode is set; show set-up while `false`.
        @Published public private(set) var isEnabled: Bool

        @Published public private(set) var isBiometricsEnabled: Bool

        private let client: PreludeAuthClient
        private let store: AppLockStore
        private let unlockReason: String
        private let lockOnStart: Bool
        private let mutex = NSLock()
        private var policy: IdleLockPolicy
        private var observers: [NSObjectProtocol] = []

        /// `lockOnStart` seals in ``start()`` so relaunching is not a
        /// way past the lock; pass `false` when rebuilding mid-session.
        public init(
            client: PreludeAuthClient,
            threshold: TimeInterval,
            unlockReason: String = "Unlock to continue",
            lockOnStart: Bool = true,
            maxAttempts: Int = PreludeIdleLock.defaultMaxAttempts
        ) {
            self.client = client
            self.unlockReason = unlockReason
            self.lockOnStart = lockOnStart
            let store = AppLockStore(domain: client.domain, maxAttempts: maxAttempts)
            self.store = store
            isEnabled = store.hasPasscode
            isBiometricsEnabled = store.isBiometricsEnabled
            policy = IdleLockPolicy(threshold: threshold)
        }

        deinit {
            for observer in observers {
                NotificationCenter.default.removeObserver(observer)
            }
        }

        // MARK: - Enrollment

        /// Also drops the biometric shortcut, armed against the old one.
        @MainActor
        public func setPasscode(_ passcode: String) throws {
            try store.setPasscode(passcode)
            isEnabled = true
            isBiometricsEnabled = false
        }

        public var isBiometricsAvailable: Bool {
            store.isBiometricsAvailable
        }

        /// Requires a passcode, so there is always a way in.
        @MainActor
        public func enableBiometrics() throws {
            try store.enableBiometrics()
            isBiometricsEnabled = true
        }

        @MainActor
        public func disableBiometrics() {
            store.disableBiometrics()
            isBiometricsEnabled = false
        }

        /// Call on sign-out.
        @MainActor
        public func disable() {
            store.clear()
            isEnabled = false
            isBiometricsEnabled = false
            isLocked = false
        }

        // MARK: - Observing

        /// Start observing. Idempotent.
        public func start() {
            mutex.lock()
            let alreadyStarted = !observers.isEmpty
            if observers.isEmpty {
                // `queue: nil` delivers on the posting thread, so the
                // timestamp lands before the app suspends.
                let center = NotificationCenter.default
                observers = [
                    center.addObserver(
                        forName: UIApplication.didEnterBackgroundNotification,
                        object: nil,
                        queue: nil
                    ) { [weak self] _ in
                        self?.markBackgrounded()
                    },
                    center.addObserver(
                        forName: UIApplication.willEnterForegroundNotification,
                        object: nil,
                        queue: nil
                    ) { [weak self] _ in
                        self?.sealIfIdle()
                    },
                ]
            }
            mutex.unlock()

            guard !alreadyStarted, lockOnStart, isEnabled else {
                return
            }
            Task { @MainActor [weak self] in
                await self?.lock()
            }
        }

        public func stop() {
            mutex.lock()
            defer { mutex.unlock() }
            for observer in observers {
                NotificationCenter.default.removeObserver(observer)
            }
            observers = []
        }

        // MARK: - Locking

        /// Lock now. Does nothing when signed out or with no
        /// credential armed; there would be no way back in.
        @MainActor
        public func lock() async {
            guard isEnabled else {
                return
            }
            isLocked = await client.seal()
        }

        /// Throws `invalidPasscode` while attempts remain and
        /// `lockedOut` once they are spent.
        public func unlock(passcode: String) async throws {
            let store = store
            try await Task.detached { try store.verify(passcode: passcode) }.value
            await lift()
        }

        /// Throws when no shortcut is armed or the match fails.
        public func unlockWithBiometrics() async throws {
            let store = store
            let reason = unlockReason
            // The read blocks its thread while the sheet is up.
            try await Task.detached { try store.verifyBiometrics(reason: reason) }.value
            await lift()
        }

        private func lift() async {
            await client.unseal()
            await MainActor.run { self.isLocked = false }
        }

        /// Drop the lock without authenticating; for use after sign-out.
        @MainActor
        public func clear() {
            isLocked = false
        }

        // MARK: - Private

        private func markBackgrounded() {
            mutex.lock()
            defer { mutex.unlock() }
            policy.markBackgrounded()
        }

        private func sealIfIdle() {
            mutex.lock()
            let idle = policy.shouldSealOnForeground()
            mutex.unlock()

            guard idle, isEnabled else {
                return
            }

            // Published before the app draws, so no view reads session
            // state unlocked. Withdrawn if there was nothing to seal.
            isLocked = true
            Task { [weak self, client] in
                let sealed = await client.seal()
                if !sealed {
                    await MainActor.run { self?.isLocked = false }
                }
            }
        }
    }

#endif
