import CryptoKit
import Foundation
import Security

struct PKCEGenerator {
    static func generate() -> (verifier: String, challenge: String) {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)

        let verifier = base64url(Data(bytes))

        let challengeData = Data(SHA256.hash(data: Data(verifier.utf8)))
        let challenge = base64url(challengeData)

        return (verifier, challenge)
    }

    private static func base64url(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
