import Foundation

struct DecodedJWT {
    let claims: [(String, String)]
    let expiresAt: Date?
    let issuedAt: Date?
    let subject: String?
}

enum JWTDecoder {

    static func decode(_ jwt: String) -> DecodedJWT? {
        let parts = jwt.split(separator: ".")
        guard parts.count >= 2 else { return nil }

        let payload = String(parts[1])

        guard let data = base64URLDecode(payload),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }

        let expiresAt: Date? = (json["exp"] as? TimeInterval).map {
            Date(timeIntervalSince1970: $0)
        }

        let issuedAt: Date? = (json["iat"] as? TimeInterval).map {
            Date(timeIntervalSince1970: $0)
        }

        let subject = json["sub"] as? String

        let claims: [(String, String)] = json.keys.sorted().map { key in
            let value = json[key]!
            return (key, stringValue(value))
        }

        return DecodedJWT(
            claims: claims,
            expiresAt: expiresAt,
            issuedAt: issuedAt,
            subject: subject
        )
    }

    private static func base64URLDecode(_ string: String) -> Data? {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        let remainder = base64.count % 4
        if remainder > 0 {
            base64.append(String(repeating: "=", count: 4 - remainder))
        }

        return Data(base64Encoded: base64)
    }

    private static func stringValue(_ value: Any) -> String {
        switch value {
        case let string as String:
            return string
        case let number as NSNumber:
            return number.stringValue
        case let array as [Any]:
            let items = array.map { stringValue($0) }
            return "[\(items.joined(separator: ", "))]"
        case let dict as [String: Any]:
            return String(data: (try? JSONSerialization.data(withJSONObject: dict)) ?? Data(),
                          encoding: .utf8) ?? "\(dict)"
        default:
            return "\(value)"
        }
    }
}
