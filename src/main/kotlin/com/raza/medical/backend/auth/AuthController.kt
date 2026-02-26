package com.raza.medical.backend.auth

import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier
import com.google.api.client.util.Value
import com.raza.medical.backend.GithubProperties
import org.springframework.http.HttpHeaders
import com.raza.medical.backend.user.entity.Role
import com.raza.medical.backend.user.entity.User
import com.raza.medical.backend.user.repository.UserRepository
import com.raza.medical.backend.security.JwtService
import com.raza.medical.backend.user.service.UserService
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.http.HttpEntity
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.RestTemplate
import java.time.LocalDateTime
import java.util.UUID

@RestController
@RequestMapping("/auth")
class AuthController(
    private val userRepository: UserRepository,
    private val passwordEncoder: BCryptPasswordEncoder,
    private val jwtService: JwtService,
    private val googleIdTokenVerifier: GoogleIdTokenVerifier,
    private val userService: UserService,
    private val restTemplate: RestTemplate = RestTemplate(),
    private val props: GithubProperties
) {

    @PostMapping("/register")
    fun register(@RequestBody request: RegisterRequest): ResponseEntity<Any> {
        val otp = generateOtp()
        val expiry = System.currentTimeMillis() + (5 * 60 * 1000)

        val user = User(
            email = request.email,
            password = passwordEncoder.encode(request.password)!!,
            role = request.role,
            isVerified = false,
            otp = otp,
            otpExpiry = expiry
        )

        userRepository.save(user)

        println("Generated OTP for ${request.email}: $otp")

        return ResponseEntity.ok(
            mapOf(
                "message" to "User registered. Please verify OTP."
            )
        )
    }

    @PostMapping("/verify-otp")
    fun verifyOtp(@RequestBody request: VerifyOtpRequest): RegisterResponse {

        val user = userRepository.findByEmail(request.email)
            ?: throw RuntimeException(
                "User not found"
            )

        if (user.isVerified) {
            return RegisterResponse(
                "User already verified"
            )
        }

        if (user.otp != request.otp) {
            throw RuntimeException(
                "Invalid otp"
            )
        }

        if (user.otpExpiry == null ||
            System.currentTimeMillis() > user.otpExpiry!!
        ) {
            throw RuntimeException(
                "OTP expired"
            )
        }

        user.isVerified = true
        user.otp = null
        user.otpExpiry = null

        userRepository.save(user)

        return RegisterResponse(
            "User verified successfully"
        )
    }

    private fun generateOtp(): String {
        return (100000..999999).random().toString()
    }

    @PostMapping("/login")
    fun login(@RequestBody request: LoginRequest): AuthResponse {
        val user = userRepository.findByEmail(request.email)
            ?: throw RuntimeException("User not found")

        if (!passwordEncoder.matches(request.password, user.password)) {
            throw RuntimeException("Invalid password")
        }

        if (!user.isVerified) {
            throw RuntimeException("Email not verified")
        }

        val token = jwtService.generateToken(user)
        return AuthResponse(token)
    }

    data class ForgotPasswordRequest(
        val email: String
    )

    data class ForgotPasswordResponse(
        val resetLink: String
    )

    data class ResetPasswordRequest(
        val token: String,
        val newPassword: String
    )

    @PostMapping("/forgot-password")
    fun forgotPassword(@RequestBody req: ForgotPasswordRequest):
            ResponseEntity<Any> {
        val user = userRepository.findByEmail(req.email)
            ?: return ResponseEntity.ok(
                "If account exists, reset link generated"
            )

        val token = UUID.randomUUID().toString()
        val expiry = LocalDateTime.now().plusMinutes(15)

        user.resetToken = token
        user.resetTokenExpiry = expiry
        userRepository.save(user)

        val link = "myapp://resetPassword?token=$token"

        return ResponseEntity.ok(
            ForgotPasswordResponse(link)
        )
    }

    @PostMapping("/reset-password")
    fun resetPassword(@RequestBody req: ResetPasswordRequest):
            ResponseEntity<ResetPasswordResponse> {
        val user: User = userRepository.findByResetToken(req.token)
            ?: return ResponseEntity.badRequest().body(
                ResetPasswordResponse(
                    false,
                    "Invalid Token"
                )
            )

        if (user.resetTokenExpiry!!.isBefore(
                LocalDateTime.now()
            )
        ) {
            return ResponseEntity.badRequest().body(
                ResetPasswordResponse(
                    false,
                    "Token expired"
                )
            )
        }

        user.password = passwordEncoder.encode(req.newPassword)!!
        user.resetToken = null
        user.resetTokenExpiry = null
        userRepository.save(user)

        return ResponseEntity.ok(
            ResetPasswordResponse(
                true,
                "Password updated"
            )
        )

    }

    @PostMapping("/google")
    fun loginWithGoogle(
        @RequestBody request: GoogleLoginRequest): ResponseEntity<Any> {

        val idToken = googleIdTokenVerifier.verify(request.idToken)
            ?: return ResponseEntity.status(
                HttpStatus.UNAUTHORIZED
            ).body(
                "invalid token"
            )

        val payload = idToken.payload

        val email = payload.email
        val googleId = payload.subject
        val name = payload["name"] as String?

        val user = userService.findOrCreateGoogleUser(email, googleId, name)

        val accessToken = jwtService.generateToken(user)
        val refreshToken = jwtService.generateToken(user)

        return ResponseEntity.ok(
            mapOf(
                "userId" to user.id,
                "accessToken" to accessToken,
                "refreshToken" to refreshToken
            )
        )
    }

    @PostMapping("/facebook")
    fun loginWithFacebook(@RequestBody request: FacebookLoginRequest):
            ResponseEntity<Any> {

        val fbUser= verifyFacebookToken(request.accessToken!!)

        val user = userRepository.findByFacebookId(fbUser.id!!)
            ?: userRepository.save(
                User(
                    email = fbUser.email!!,
                    name = fbUser.name,
                    facebookId = fbUser.id,
                    provider = "FACEBOOK",
                    password = ""
                )
            )

        val jwt = jwtService.generateToken(user)

        return ResponseEntity.ok(FacebookLoginResponse(jwt, "${user.id}"))
    }

    private fun verifyFacebookToken(token: String):
            FacebookUser {
        val url = "https://graph.facebook.com/me?fields=id,name,email&access_token=$token"

        val response = restTemplate.getForEntity(url, FacebookUser::class.java)

        if(!response.statusCode.is2xxSuccessful ||
            response.body == null) {
            throw RuntimeException(
                "Invalid Facebook token"
            )
        }

        return response.body!!
    }

    @PostMapping("/github")
    fun loginWithGithub(@RequestBody request: GithubLoginRequest):
            ResponseEntity<Any> {

        val githubUser = verifyGithubCode(request.code!!)

        var user = userRepository.findByGithubId(githubUser.id!!)

        if(user != null) {
            user.githubId = githubUser.id
            user = userRepository.save(user)

        } else {
            user = userRepository.findByEmail(githubUser.email!!)

            if(user == null) {
                user = userRepository.save(
                    User(
                        email = githubUser.email ?: "",
                        name = githubUser.name?:githubUser.login,
                        githubId = githubUser.id,
                        provider= "GITHUB",
                        password = ""
                    )
                )
            }
        }

        val jwt = jwtService.generateToken(user!!)

        return ResponseEntity.ok(
            GithubLoginResponse(
                token = jwt,
                userId = "${user.id}"
            )
        )
    }

    private fun verifyGithubCode(code: String): GithubUser {

        val tokenUrl = "https://github.com/login/oauth/access_token"

        val tokenRequest = LinkedMultiValueMap<String, String>()
            .apply {
                add("client_id", props.clientId)
                add("client_secret", props.clientSecret)
                add("code", code)
            }

        val tokenHeaders = HttpHeaders().apply {
            accept = listOf(MediaType.APPLICATION_JSON)
        }

        val tokenEntity = HttpEntity(
            tokenRequest,
            tokenHeaders)

        val tokenResponse = restTemplate.postForEntity(
            tokenUrl, tokenEntity, GithubTokenResponse::class.java
        )

        println("response: ${tokenResponse.body}")

        if(!tokenResponse.statusCode.is2xxSuccessful||
            tokenResponse.body==null) {
            throw RuntimeException("Invalid github code")
        }

        val accessToken = tokenResponse.body!!.access_token

        val userHeaders = HttpHeaders().apply {
            setBearerAuth(accessToken!!)
        }

        val userEntity = HttpEntity<Void>(userHeaders)

        val userResponse = restTemplate.exchange(
            "https://api.github.com/user",
            HttpMethod.GET,
            userEntity,
            GithubUser::class.java
        )

        if(!userResponse.statusCode.is2xxSuccessful||
            userResponse.body == null) {
            throw RuntimeException("invalid github code")
        }

        val githubUser = userResponse.body

        val emailResponse = restTemplate.exchange(
            "https://api.github.com/user/emails",
            HttpMethod.GET,
            userEntity,
            Array<GithubEmail>::class.java
        )

        val email = emailResponse.body
            ?.firstOrNull {
                it.primary!! && it.verified!!
            }
            ?.email

        return githubUser?.copy(email = email)!!
    }
}

data class GithubEmail(
    var email: String? = null,
    var primary: Boolean? = false,
    var verified: Boolean? = false
)

class GithubLoginRequest {
    var code: String?= null
}

data class GithubLoginResponse (
    var token: String? = null,
    var userId: String? = null
)

class GithubTokenRequest {
}

data class GithubTokenResponse (
    val access_token: String? = null,
    val token_type: String? = null,
    val scope: String? = null
)

data class GithubUser(
    var id: String? = null,
    var login: String? = null,
    var name: String? = null,
    var email: String? = null
)

data class FacebookLoginResponse(
    var jwt: String? = null,
    var id: String? = null
)

data class FacebookLoginRequest(
    var accessToken: String? = null
)

data class FacebookUser(
    var id: String? = null,
    var name: String? = null,
    var email: String? = null
)

data class ResetPasswordResponse(
    var result: Boolean? = false,
    var message: String? = null
)

data class GoogleLoginRequest(
    val idToken: String
)

data class RegisterRequest(
    val email: String,
    val password: String,
    val role: Role = Role.DOCTOR
)

data class LoginRequest(
    val email: String,
    val password: String
)

data class AuthResponse(
    val token: String
)

data class RegisterResponse(
    val message: String
)

data class VerifyOtpRequest(
    val email: String,
    val otp: String
)