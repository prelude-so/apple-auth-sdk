import Foundation

struct APIErrorJSON: Decodable {
    var code: String
    var message: String?
    var type: String?
    var requestId: String?

    enum CodingKeys: String, CodingKey {
        case code
        case message
        case type
        case requestId = "request_id"
    }

    var displayMessage: String {
        message.map { $0.isEmpty ? code : $0 } ?? code
    }
}

extension APIErrorJSON {
    /// Caps the cost of a giant non-JSON error page.
    static let maxBodyBytes = 4 * 1024

    /// The API error of a non-2xx response, or nil.
    static func decode(_ data: Data, response: HTTPURLResponse) -> Self? {
        guard !(200 ..< 300).contains(response.statusCode), data.count <= maxBodyBytes else {
            return nil
        }
        return try? JSONDecoder().decode(Self.self, from: data)
    }
}
