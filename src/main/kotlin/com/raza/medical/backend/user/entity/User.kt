package com.raza.medical.backend.user.entity

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.LocalDateTime

@Entity
@Table(name = "users")
data class User(

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long = 0,

    @Column(unique = true)
    val email: String,

    var password: String?,

    @Enumerated(EnumType.STRING)
    val role: Role = Role.DOCTOR,

    var isVerified: Boolean = false,

    var otp: String? = null,

    var otpExpiry: Long? = null,

    var resetToken: String? = null,

    var resetTokenExpiry: LocalDateTime? = null,

    var googleId: String? = null,

    var name: String? = null,

    var facebookId: String? = null,

    var provider: String? = null
)

enum class Role {
    DOCTOR,
    PATIENT
}