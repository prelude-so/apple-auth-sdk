import AuthenticationServices
import Foundation
import PreludeAuth
#if canImport(UIKit)
    import UIKit
#endif

/// Presents a web authentication session and resolves the callback
/// URL. Abstracted so flows can be exercised without UI.
protocol WebAuthPresenting: Sendable {
    func authenticate(
        url: URL,
        callbackScheme: String,
        prefersEphemeralSession: Bool
    ) async throws -> URL
}

/// `ASWebAuthenticationSession`-backed presenter.
@MainActor
final class WebAuthPresenter: NSObject, WebAuthPresenting {
    private var activeSession: ASWebAuthenticationSession?

    override init() {
        super.init()
    }

    func authenticate(
        url: URL,
        callbackScheme: String,
        prefersEphemeralSession: Bool
    ) async throws -> URL {
        try await withTaskCancellationHandler(
            operation: {
                try await start(
                    url: url,
                    callbackScheme: callbackScheme,
                    prefersEphemeralSession: prefersEphemeralSession
                )
            },
            onCancel: {
                Task { @MainActor in self.activeSession?.cancel() }
            }
        )
    }

    private func start(
        url: URL,
        callbackScheme: String,
        prefersEphemeralSession: Bool
    ) async throws -> URL {
        // Cleared here (actor-isolated) rather than in the
        // completion, which the SDK treats as nonisolated.
        defer { activeSession = nil }
        return try await withCheckedThrowingContinuation { continuation in
            // The system invokes the completion at most once; the
            // flag also covers the synchronous `start()` failure.
            // Reference-typed so the completion closure mutates no
            // captured locals.
            let resumed = ResumeFlag()
            func resume(_ result: Result<URL, Error>) {
                guard resumed.trySet() else { return }
                continuation.resume(with: result)
            }

            let session = ASWebAuthenticationSession(
                url: url,
                callbackURLScheme: callbackScheme
            ) { callbackURL, error in
                if let callbackURL {
                    resume(.success(callbackURL))
                } else {
                    resume(.failure(Self.mapError(error)))
                }
            }
            session.prefersEphemeralWebBrowserSession = prefersEphemeralSession
            session.presentationContextProvider = self
            activeSession = session

            if !session.start() {
                resume(.failure(PreludeAuthError.invalidConfiguration(
                    "Unable to present the web authentication session"
                )))
            }
        }
    }

    /// One-shot latch for continuation resumption.
    private final class ResumeFlag {
        private var resumed = false

        /// Returns `true` exactly once.
        func trySet() -> Bool {
            guard !resumed else { return false }
            resumed = true
            return true
        }
    }

    private static func mapError(_ error: Error?) -> Error {
        if let error = error as? ASWebAuthenticationSessionError,
           error.code == .canceledLogin {
            return PreludeAuthError.cancelled
        }
        return PreludeAuthError.network(underlying: error ?? URLError(.unknown))
    }
}

extension WebAuthPresenter: ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(
        for _: ASWebAuthenticationSession
    ) -> ASPresentationAnchor {
        #if canImport(UIKit)
            let keyWindow = UIApplication.shared.connectedScenes
                .compactMap { $0 as? UIWindowScene }
                .flatMap(\.windows)
                .first(where: \.isKeyWindow)
            return keyWindow ?? ASPresentationAnchor()
        #else
            return ASPresentationAnchor()
        #endif
    }
}
