package com.raza.medical.backend.controller

import com.raza.medical.backend.model.Role
import com.raza.medical.backend.model.User
import com.raza.medical.backend.repository.UserRepository
import com.raza.medical.backend.security.JwtService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/auth")
class AuthController(
    private val userRepository: UserRepository,
    private val passwordEncoder: BCryptPasswordEncoder,
    private val jwtService: JwtService
) {

    data class RegisterRequest(
        val email: String,
        val password: String,
        val role: Role
    )

    data class LoginRequest(
        val email: String,
        val password: String
    )

    data class AuthResponse(
        val token: String
    )

    @PostMapping("/register")
    fun register(@RequestBody request: RegisterRequest): User {
        val user = User(
            email = request.email,
            password = passwordEncoder.encode(request.password)!!,
            role = request.role
        )
        return userRepository.save(user)
    }

    @PostMapping("/login")
    fun login(@RequestBody request: LoginRequest): AuthResponse {
        val user = userRepository.findByEmail(request.email)
            ?: throw RuntimeException("User not found")

        if (!passwordEncoder.matches(request.password, user.password)) {
            throw RuntimeException("Invalid password")
        }

        val token = jwtService.generateToken(user)
        return AuthResponse(token)
    }
}