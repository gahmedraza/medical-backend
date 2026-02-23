package com.raza.medical.backend.user.service

import com.raza.medical.backend.user.entity.User
import com.raza.medical.backend.user.repository.UserRepository
import org.springframework.stereotype.Service

@Service
class UserService(
    private val userRepository: UserRepository
) {
    fun findOrCreateGoogleUser(
        email: String,
        googleId: String,
        name: String?
    ): User {
        val existing = userRepository.findByEmail(email)

        if(existing != null) {
            return existing
        }

        val newUser = User(
            email = email,
            password = null,
            googleId = googleId,
            name = name,
            isVerified = true
        )

        return userRepository.save(newUser)
    }
}