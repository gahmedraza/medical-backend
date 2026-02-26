package com.raza.medical.backend

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "github")
data class GithubProperties(
    val clientId: String,
    val clientSecret: String
)