import Foundation

/// Permissive HTTP `Date:` header parser. RFC 7231 §7.1.1.1 allows
/// three formats — `IMF-fixdate` (canonical), and the obsolete
/// `rfc850-date` and `asctime-date`. ``DateFormatter`` only matches
/// one pattern at a time, so we try each in turn and fall through
/// to `nil` for anything unparseable.
enum HTTPDate {
    static func parse(_ header: String) -> Date? {
        for formatter in formatters {
            if let date = formatter.date(from: header) {
                return date
            }
        }
        return nil
    }

    private static let formatters: [DateFormatter] = [
        formatter("EEE, dd MMM yyyy HH:mm:ss 'GMT'"), // IMF-fixdate
        formatter("EEEE, dd-MMM-yy HH:mm:ss 'GMT'"), // RFC 850
        formatter("EEE MMM d HH:mm:ss yyyy"), // asctime (single-space)
        formatter("EEE MMM  d HH:mm:ss yyyy"), // asctime (double-space, day < 10)
    ]

    private static func formatter(_ format: String) -> DateFormatter {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = format
        return formatter
    }
}
