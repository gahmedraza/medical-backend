package com.raza.medical.backend.security

import com.raza.medical.backend.model.User
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import org.springframework.stereotype.Service
import java.util.Date

@Service
class JwtService {

    val secretKey = Keys.secretKeyFor(
        SignatureAlgorithm.HS256
    )

    fun generateToken(user: User): String {
        return Jwts.builder()
            .setSubject(user.email)
            .claim("role", user.role.name)
            .setIssuedAt(Date())
            .setExpiration(
                Date(
                    System.currentTimeMillis() +
                            1000 * 60 * 60 * 24
                )
            )
            .signWith(secretKey)
            .compact()
    }
}