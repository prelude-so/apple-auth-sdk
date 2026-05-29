import Foundation

/// SDK version + transport-layer identification.
///
/// Format: `Prelude/<sdk-version> (<platform>; <os name> <os version>)`
///
/// Platform and OS version are included so server-side telemetry
/// can distinguish iOS / macOS / tvOS deployments without forcing
/// the host app to surrender its own `User-Agent`.
///
/// ``version`` is the source of truth; release tooling rewrites
/// this constant alongside the package tag.
enum PreludeAuthSDK {
    /// Semantic version of the PreludeAuth package. Bumped at
    /// release time and included in the `User-Agent` of every
    /// outgoing request.
    static let version = "0.4.0"

    /// `User-Agent` value attached to every outgoing request.
    static let userAgent: String = {
        let osVersionInfo = ProcessInfo.processInfo.operatingSystemVersion
        let osVersion = "\(osVersionInfo.majorVersion).\(osVersionInfo.minorVersion).\(osVersionInfo.patchVersion)"
        return "Prelude/\(version) (Apple; \(platformName) \(osVersion))"
    }()

    private static var platformName: String {
        #if os(iOS)
            return "iOS"
        #elseif os(macOS)
            return "macOS"
        #elseif os(tvOS)
            return "tvOS"
        #elseif os(watchOS)
            return "watchOS"
        #elseif os(visionOS)
            return "visionOS"
        #else
            return "unknown"
        #endif
    }
}
