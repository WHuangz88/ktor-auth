package xyz.whuangz

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import xyz.whuangz.authenticate
import xyz.whuangz.data.requests.AuthRequest
import xyz.whuangz.data.responses.AuthResponse
import xyz.whuangz.data.user.User
import xyz.whuangz.data.user.UserDataSource
import xyz.whuangz.security.hashing.HashingService
import xyz.whuangz.security.hashing.SaltedHash
import xyz.whuangz.security.token.TokenClaim
import xyz.whuangz.security.token.TokenConfig
import xyz.whuangz.security.token.TokenService

fun Route.signUp(
    hashingService: HashingService,
    userDataSource: UserDataSource
) {
    post("signup") {
        val req = context.receiveNullable<AuthRequest>() ?: kotlin.run {
            context.respond(HttpStatusCode.BadRequest)
            return@post
        }

        val areFieldsBlank = req.username.isBlank() || req.password.isBlank()
        val isPwdTooShort = req.password.length < 8
        if (areFieldsBlank || isPwdTooShort) {
            context.respond(HttpStatusCode.Conflict)
            return@post
        }

        val saltedHash = hashingService.generateSaltedHash(req.password)
        val user = User(
            username = req.username,
            password = saltedHash.hash,
            salt = saltedHash.salt
        )

        val wasAck = userDataSource.insertUser(user)
        if (!wasAck) {
            context.respond(HttpStatusCode.Conflict)
            return@post
        }

        context.respond(HttpStatusCode.OK)
    }
}

fun Route.signIn(
    userDataSource: UserDataSource,
    hashingService: HashingService,
    tokenService: TokenService,
    tokenConfig: TokenConfig
) {
    post("signin") {
        val req = context.receiveNullable<AuthRequest>() ?: kotlin.run {
            context.respond(HttpStatusCode.BadRequest)
            return@post
        }

        val user = userDataSource.getUserByUsername(req.username)
        if (user == null) {
            context.respond(HttpStatusCode.Conflict, "Incorrect username or password")
            return@post
        }

        val isValidPassword = hashingService.verify(
            value = req.password,
            saltedHash = SaltedHash(
                hash =  user.password,
                salt = user.salt
            )
        )

        if (!isValidPassword) {
            context.respond(HttpStatusCode.Conflict, "Incorrect username or password")
            return@post
        }

        val token = tokenService.generate(
            config = tokenConfig,
            TokenClaim(
                name = "userId",
                value =  user.id.toString()
            )
        )
        context.respond(
            HttpStatusCode.OK,
            AuthResponse(
                token = token
            )
        )
    }
}

fun Route.authenticate() {
    authenticate {
        get("authenticate") {
            context.respond(HttpStatusCode.OK)
        }
    }
}

fun Route.getSecretInfo() {
    authenticate {
        get("secret") {
            val principle = context.principal<JWTPrincipal>()
            val userId = principle?.getClaim("userId", String::class)
            context.respond(
                HttpStatusCode.OK,
                "Your userid is $userId"
            )
        }
    }
}