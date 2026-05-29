import Foundation

/// URL for the DPoP `htu` claim. Must match the server's
/// reconstruction (`scheme://Host-header/path`) when a `Host:`
/// override is in effect. RFC 9449 §4.2 excludes query and
/// fragment.
enum DPoPHtu {
    static func url(for request: URLRequest) -> URL? {
        guard let url = request.url,
              var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return nil
        }
        components.query = nil
        components.fragment = nil
        // Scheme and host are case-insensitive (RFC 3986 §6.2.2.1)
        // and the server's reconstruction normalises them; mirror
        // that here so a mixed-case base URL still produces a
        // matching proof.
        components.scheme = components.scheme?.lowercased()
        components.host = components.host?.lowercased()

        if let hostOverride = request.value(forHTTPHeaderField: HTTPHeader.host),
           !hostOverride.isEmpty {
            // Use the Host header verbatim, lowercased (port
            // included) so the client `htu` matches byte-for-byte.
            // `percentEncodedPath` keeps the original encoding.
            let scheme = components.scheme ?? "https"
            return URL(string: "\(scheme)://\(hostOverride.lowercased())\(components.percentEncodedPath)")
        }

        return components.url
    }
}
