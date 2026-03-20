import Foundation

struct UserProfile: Codable {
    let id: UUID
    let username: String
    let role: Role
    let isActive: Bool

    enum Role: String, Codable {
        case user = "user"
        case admin = "admin"
    }

    enum CodingKeys: String, CodingKey {
        case id
        case username
        case role
        case isActive = "is_active"
    }
}
