package xyz.whuangz

import com.plcoding.plugins.configureSecurity
import io.ktor.server.application.*
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.litote.kmongo.coroutine.*
import org.litote.kmongo.reactivestreams.KMongo
import xyz.whuangz.data.user.MongUserDataSource
import xyz.whuangz.data.user.User
import xyz.whuangz.plugins.*
import xyz.whuangz.security.hashing.SHA256HashingService
import xyz.whuangz.security.token.JWTTokenService
import xyz.whuangz.security.token.TokenConfig

fun main(args: Array<String>): Unit =
    io.ktor.server.netty.EngineMain.main(args)

@Suppress("unused") // application.conf references the main function. This annotation prevents the IDE from marking it as unused.
fun Application.module() {
    val mongoPwd = System.getenv("MONGO_PWD")
    var dbName = "ktor-auth"
    val db = KMongo.createClient(
        connectionString = "mongodb+srv://whuangz:$mongoPwd@cluster0.fk4tdjz.mongodb.net/$dbName?retryWrites=true&w=majority"
    ).coroutine
        .getDatabase(dbName)

    val userDataSource = MongUserDataSource(db)
    val tokenService = JWTTokenService()
    val tokenConfig = TokenConfig(
        issuer = environment.config.property("jwt.issuer").getString(),
        audience = environment.config.property("jwt.audience").getString(),
        expiresIn = 356L * 1000L * 60L * 60L,
        secret = System.getenv("JWT_SECRET")
    )

    val hashingService = SHA256HashingService()

    configureSecurity(tokenConfig)
    configureRouting(userDataSource, hashingService, tokenService, tokenConfig)
    configureSerialization()
    configureMonitoring()

}
