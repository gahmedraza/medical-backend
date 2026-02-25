package com.raza.medical.backend.user.repository

import com.raza.medical.backend.user.entity.User
import org.springframework.data.jpa.repository.JpaRepository

interface UserRepository : JpaRepository<User, Long> {
    fun findByEmail(email: String): User?

    fun findByResetToken(resetToken: String): User?

    fun findByFacebookId(facebookId: String): User?

    fun findByGithubId(githubId: String): User?
}