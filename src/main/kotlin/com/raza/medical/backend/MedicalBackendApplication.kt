package com.raza.medical.backend

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication

@SpringBootApplication
@EnableConfigurationProperties(
    GithubProperties::class
)
class MedicalBackendApplication

fun main(args: Array<String>) {
	runApplication<MedicalBackendApplication>(*args)
}
