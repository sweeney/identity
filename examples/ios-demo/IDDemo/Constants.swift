import Foundation

enum Constants {
    enum OAuth {
        static let baseURL = "https://id.swee.net"
        static let authorizeEndpoint = "/oauth/authorize"
        static let tokenEndpoint = "/oauth/token"
        static let profileEndpoint = "/api/v1/auth/me"
        static let logoutEndpoint = "/api/v1/auth/logout"
        static let clientID = "net.swee.iddemo"
        static let redirectURI = "idswee://callback"
        static let callbackScheme = "idswee"
    }
}
