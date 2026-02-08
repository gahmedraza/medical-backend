package com.raza.medical.backend.controller

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class HealthController {

    @GetMapping("/health")
    fun health(): String {
        return "Backend is running"
    }

    @GetMapping("/doctor/profile")
    fun doctorProfile(): String {
        return "Doctor profile secured"
    }
}