import Foundation

/// SDK version + transport-layer identification.
///
/// ``version`` is the source of truth for releases: the publish scripts
/// read it and validate the tag against it.
enum PreludeAuthSDK {
    /// Semantic version of the PreludeAuth package. Bumped at
    /// release time and included in the `User-Agent` of every
    /// outgoing request.
    static let version = "0.8.0"

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
