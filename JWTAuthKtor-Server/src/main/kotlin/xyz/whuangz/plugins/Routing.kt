package xyz.whuangz.plugins

import io.ktor.server.routing.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.request.*
import xyz.whuangz.authenticate
import xyz.whuangz.data.user.UserDataSource
import xyz.whuangz.getSecretInfo
import xyz.whuangz.security.hashing.HashingService
import xyz.whuangz.security.token.TokenConfig
import xyz.whuangz.security.token.TokenService
import xyz.whuangz.signIn
import xyz.whuangz.signUp

fun Application.configureRouting(
    userDataSource: UserDataSource,
    hashingService: HashingService,
    tokenService: TokenService,
    tokenConfig: TokenConfig
) {
    routing {
        signIn(userDataSource, hashingService, tokenService, tokenConfig)
        signUp(hashingService, userDataSource)
        authenticate()
        getSecretInfo()
    }
}
