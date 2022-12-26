package xyz.whuangz.jwtauthktor.auth

data class AuthRequest(
    val username: String,
    val password: String
)