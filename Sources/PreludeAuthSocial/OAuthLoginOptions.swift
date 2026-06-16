import Foundation
import PreludeAuth

/// Options for ``PreludeAuthClient/loginWithOAuth(_:)``.
public struct OAuthLoginOptions: Sendable {
    /// Provider to authenticate against.
    public var provider: OAuthProvider

    /// Where the server redirects once authentication completes.
    /// Must use the app's custom URL scheme (e.g. `myapp://oauth`)
    /// and be allowlisted by the app's configuration.
    public var redirectURI: URL

    /// When `true` the web session shares no cookies with Safari,
    /// so every login starts from a clean slate. Defaults to
    /// `false` so returning users can reuse their provider session.
    public var prefersEphemeralSession: Bool

    public init(
        provider: OAuthProvider,
        redirectURI: URL,
        prefersEphemeralSession: Bool = false
    ) {
        self.provider = provider
        self.redirectURI = redirectURI
        self.prefersEphemeralSession = prefersEphemeralSession
    }
}
