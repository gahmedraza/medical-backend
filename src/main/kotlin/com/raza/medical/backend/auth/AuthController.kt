package com.raza.medical.backend.auth

import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier
import com.raza.medical.backend.user.entity.Role
import com.raza.medical.backend.user.entity.User
import com.raza.medical.backend.user.repository.UserRepository
import com.raza.medical.backend.security.JwtService
import com.raza.medical.backend.user.service.UserService
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.time.LocalDateTime
import java.util.UUID

@RestController
@RequestMapping("/auth")
class AuthController(
    private val userRepository: UserRepository,
    private val passwordEncoder: BCryptPasswordEncoder,
    private val jwtService: JwtService,
    private val googleIdTokenVerifier: GoogleIdTokenVerifier,
    private val userService: UserService
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
}

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