package com.raza.medical.backend.config

import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier
import com.google.api.client.http.javanet.NetHttpTransport
import com.google.api.client.json.jackson2.JacksonFactory
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class GoogleConfig {
    @Bean
    fun googleIdTokenVerifier(): GoogleIdTokenVerifier {
        val transport = NetHttpTransport()

        val jsonFactory = JacksonFactory.getDefaultInstance()

        return GoogleIdTokenVerifier
            .Builder(transport, jsonFactory)
            .setAudience(listOf(
                "878270989450-uoiusi71bi9eb24vh1h4o5b0tq90bkmv.apps.googleusercontent.com"
            ))
            .build()
    }
}