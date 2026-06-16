import Foundation

/// Value-typed facade over the session actor.
///
/// Sendable, with a synchronous throwing init, so it propagates
/// through SwiftUI surfaces (`@State`, `@Environment`) without
/// ceremony and leaves room for `@Observable` adoption. Mutable
/// state lives on a nested actor; copies of the facade share the
/// same actor instance.
public struct PreludeAuthClient: Sendable {
    let impl: Impl

    /// - Parameters:
    ///   - endpoint: API endpoint. Defaults to the canonical
    ///     Prelude address; pass `.custom("https://…")` for
    ///     staging or local development.
    ///   - hostOverride: canonical authority used as the DPoP
    ///     `htu`, the `Host:` header, and the Keychain
    ///     partition key. Set when the connection address
    ///     differs from what the server sees (e.g. localhost
    ///     forwarding behind a reverse proxy). `nil` derives
    ///     these from the endpoint's host.
    ///   - signalsDispatcher: optional anti-fraud dispatcher
    ///     wired into unauthenticated login calls.
    ///   - timeout: per-request timeout, in seconds.
    ///   - allowInsecureTLS: trust every server cert. Local
    ///     development only.
    public init(
        endpoint: Endpoint = .default,
        hostOverride: String? = nil,
        signalsDispatcher: PreludeSignalsDispatcher? = nil,
        timeout: TimeInterval = 10.0,
        allowInsecureTLS: Bool = false
    ) throws {
        impl = try Impl(
            baseURL: endpoint.resolveBaseURL(),
            hostOverride: hostOverride,
            signalsDispatcher: signalsDispatcher,
            timeout: timeout,
            httpSession: URLSessionHTTPSession(allowInsecureTLS: allowInsecureTLS),
            clock: defaultNowProvider,
            keyStore: DPoPKeyStoreFactory.makeDefault(),
            refreshTokenStore: RefreshTokenStore(),
            accessTokenCache: AccessTokenCache(),
            deviceIDStore: DeviceIDStore()
        )
    }

    /// Test-only init that takes injected dependencies.
    init(
        baseURL: URL,
        hostOverride: String?,
        signalsDispatcher: PreludeSignalsDispatcher?,
        timeout: TimeInterval,
        httpSession: HTTPSession,
        clock: @escaping NowProvider,
        keyStore: DPoPKeyStore,
        refreshTokenStore: RefreshTokenStore,
        accessTokenCache: AccessTokenCache,
        deviceIDStore: DeviceIDStore
    ) throws {
        impl = try Impl(
            baseURL: baseURL,
            hostOverride: hostOverride,
            signalsDispatcher: signalsDispatcher,
            timeout: timeout,
            httpSession: httpSession,
            clock: clock,
            keyStore: keyStore,
            refreshTokenStore: refreshTokenStore,
            accessTokenCache: accessTokenCache,
            deviceIDStore: deviceIDStore
        )
    }

    /// Mark the local access token expired so the next protected
    /// call refreshes. Does NOT revoke the session on the server
    /// or wipe the refresh token — use ``logout()`` for that.
    /// The cached token entry stays retrievable so the client
    /// can render profile data while a refresh runs.
    public func invalidateSession() async throws {
        try await impl.invalidateSession()
    }

    /// Most-recently-issued step-up challenge, or `nil` when none
    /// is in flight. Set on `requestStepUp`, advanced on multi-
    /// step `submitStepUpOTP`, cleared on completion / logout /
    /// change-password.
    public var activeStepUp: StepUpChallenge? {
        get async { await impl.activeStepUp }
    }

    // MARK: - Static helpers (pure)

    /// Adjust a server-reported expiration (Unix seconds) to the
    /// local clock by applying the observed skew. `floor` (in
    /// `Double` space) preserves the "never overestimate" invariant
    /// for negative skews.
    static func adjustedLocalExpiresAt(
        serverExpiresAt: Int,
        timeDiffSec: TimeInterval
    ) -> Int {
        Int(floor(Double(serverExpiresAt) + timeDiffSec))
    }

    /// Decode a ``PreludeUser`` from an access token.
    static func makeUser(accessToken: String) throws -> PreludeUser {
        let jwt = try JWT.decode(accessToken)
        return PreludeUser(
            accessToken: accessToken,
            profile: PreludeProfile.from(jwt: jwt)
        )
    }
}

extension PreludeAuthClient {
    /// Owns the mutable session state; serialises access via actor
    /// isolation. Internal: never surfaced from the public facade.
    actor Impl {
        /// Keychain partition key. Derived from ``hostOverride``
        /// when set, else from ``baseURL``'s host.
        let domain: String

        /// Canonical-authority hint. When set it is (1) the
        /// Keychain partition key, (2) the DPoP `htu` authority,
        /// and (3) written as the `Host:` header on every
        /// outgoing request.
        ///
        /// Caveat: `URLSession` may silently overwrite the `Host:`
        /// header. In practice an `/etc/hosts` entry on the
        /// simulator plus a canonical ``baseURL`` is more reliable.
        let hostOverride: String?

        let signalsDispatcher: PreludeSignalsDispatcher?
        let timeout: TimeInterval
        let baseURL: URL

        let httpClient: HTTPClient
        let keyStore: DPoPKeyStore
        let refreshTokenStore: RefreshTokenStore
        let accessTokenCache: AccessTokenCache
        let clock: NowProvider

        /// Concurrent callers (explicit ``refresh()`` and the
        /// 401-driven interceptor) share this task so the
        /// single-use refresh token is never spent twice.
        var inflightRefresh: Task<PreludeUser, Error>?

        /// Coalesces concurrent ``logout()`` callers onto a single
        /// `POST /revoke`.
        var inflightLogout: Task<Void, Error>?

        /// Coalesces concurrent ``migrate(_:)`` callers onto a single
        /// `POST /migration` ⇒ `/login/finalize` round-trip. The
        /// per-token identity doesn't matter here: once any caller
        /// establishes a session the cache short-circuits the rest.
        var inflightMigration: Task<PreludeUser, Error>?

        /// Bumped on every ``logout()``. ``refresh()`` captures it
        /// at entry and bails before persisting rotated tokens if
        /// logout moved the counter mid-flight.
        var sessionEpoch: Int = 0

        /// In-memory step-up handle. Tracks the most recent
        /// challenge so callers can observe in-progress flows
        /// without holding the value themselves.
        var activeStepUp: StepUpChallenge?

        init(
            baseURL: URL,
            hostOverride: String?,
            signalsDispatcher: PreludeSignalsDispatcher?,
            timeout: TimeInterval,
            httpSession: HTTPSession,
            clock: @escaping NowProvider,
            keyStore: DPoPKeyStore,
            refreshTokenStore: RefreshTokenStore,
            accessTokenCache: AccessTokenCache,
            deviceIDStore: DeviceIDStore
        ) throws {
            let derivedDomain: String
            if let hostOverride, !hostOverride.isEmpty {
                derivedDomain = hostOverride
            } else if let host = baseURL.host, !host.isEmpty {
                derivedDomain = host
            } else {
                throw PreludeAuthError.invalidConfiguration(
                    "baseURL must have a host, or hostOverride must be non-empty"
                )
            }

            domain = derivedDomain
            self.hostOverride = hostOverride
            self.signalsDispatcher = signalsDispatcher
            self.timeout = timeout
            self.baseURL = baseURL.appendingPathComponent("v1/session")
            // Device-id is wired as a default interceptor so every
            // session request carries `X-Device-Id` without per-
            // callsite plumbing.
            httpClient = HTTPClient(
                session: httpSession,
                clock: clock,
                defaultInterceptors: [
                    DeviceIDInterceptor(domain: derivedDomain, store: deviceIDStore),
                ]
            )
            self.keyStore = keyStore
            self.refreshTokenStore = refreshTokenStore
            self.accessTokenCache = accessTokenCache
            self.clock = clock

            // Warm the in-memory cache so a cold start can render
            // the profile and skip a refresh round-trip when valid.
            //
            // Fire-and-forget: the actor's queue serialises this
            // hydrate before any subsequent isolated message from
            // the same caller, so the typical "construct ⇒ read"
            // path still sees the warmed entry. A first read that
            // races ahead just costs one extra refresh round-trip,
            // which the original synchronous warm wouldn't have
            // saved anyway when the Keychain was empty.
            Task { [accessTokenCache, derivedDomain] in
                await accessTokenCache.hydrate(domain: derivedDomain)
            }
        }

        var dpopInterceptor: DPoPInterceptor {
            DPoPInterceptor(domain: domain, keyStore: keyStore)
        }

        /// Auto-refresh interceptor bound to this actor's cache and
        /// refresh flow. Attach alongside ``dpopInterceptor`` only
        /// on protected endpoints — unauthenticated routes (e.g.
        /// `/otp`) must not use it.
        ///
        /// `self` is passed strongly: the interceptor is built on
        /// demand and lives only for the duration of the request,
        /// so it can't extend the actor's lifetime past the
        /// caller's.
        var autoRefreshInterceptor: AutoRefreshInterceptor {
            AutoRefreshInterceptor(refresher: self)
        }

        func invalidateSession() async throws {
            try await accessTokenCache.invalidate(domain: domain)
        }

        func buildRequest(
            path: String,
            method: String = "POST",
            queryItems: [URLQueryItem] = []
        ) -> URLRequest {
            let url = baseURL.appendingPathComponent(path)
            // Only round-trip through `URLComponents` when the
            // caller passed query items: avoids re-encoding a
            // clean URL on every other call site.
            let resolvedURL: URL
            if queryItems.isEmpty {
                resolvedURL = url
            } else {
                var components = URLComponents(url: url, resolvingAgainstBaseURL: false)
                components?.queryItems = queryItems
                resolvedURL = components?.url ?? url
            }
            var request = URLRequest(url: resolvedURL)
            request.httpMethod = method
            request.timeoutInterval = timeout
            // Only advertise Content-Type for methods that carry a
            // body. Strict proxies reject Content-Type without one.
            if ["POST", "PUT", "PATCH"].contains(method.uppercased()) {
                request.setValue("application/json", forHTTPHeaderField: HTTPHeader.contentType)
            }
            request.setValue("application/json", forHTTPHeaderField: HTTPHeader.accept)
            // Identify the SDK + OS to server-side telemetry without
            // shadowing the host app's own User-Agent on requests it
            // owns: this only applies to URLRequests we build here.
            request.setValue(PreludeAuthSDK.userAgent, forHTTPHeaderField: HTTPHeader.userAgent)
            if let hostOverride, !hostOverride.isEmpty {
                request.setValue(hostOverride, forHTTPHeaderField: HTTPHeader.host)
            }
            return request
        }

        /// Best-effort: a signals failure (network, timeout, server
        /// error) must never block the auth flow. Anti-fraud
        /// coverage degrades gracefully when `dispatch_id` is
        /// missing. Cooperative cancellation still propagates so
        /// structured concurrency stays correct.
        func dispatchSignalsIfConfigured() async throws -> String? {
            guard let signalsDispatcher else { return nil }
            do {
                return try await signalsDispatcher.dispatch()
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                return nil
            }
        }

        /// Persist a fresh access token, correcting for observed
        /// clock skew so the stored expiry compares correctly
        /// against the local device clock.
        func storeAccessToken(
            _ accessToken: String,
            serverExpiresAt: Int,
            timeDiffSec: TimeInterval
        ) async throws {
            try await accessTokenCache.set(
                domain: domain,
                entry: AccessTokenEntry(
                    accessToken: accessToken,
                    expiresAt: PreludeAuthClient.adjustedLocalExpiresAt(
                        serverExpiresAt: serverExpiresAt,
                        timeDiffSec: timeDiffSec
                    )
                )
            )
        }
    }
}
