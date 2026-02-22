package com.raza.medical.backend

import org.springframework.dao.DataIntegrityViolationException
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.orm.jpa.JpaSystemException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice

@RestControllerAdvice
class GlobalExceptionHandler() {

    @ExceptionHandler(JpaSystemException::class)
    fun handleJpaSystem(e: JpaSystemException):
            ResponseEntity<Map<String, String>> {

        val msg = e.rootCause?.message ?: ""

        return if (msg.contains("UNIQUE") &&
            msg.contains("users.email")
        ) {
            ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(
                    mapOf(
                        "error" to "Email already exists"
                    )
                )
        } else {
            ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(
                    mapOf(
                        "error" to "Database error"
                    )
                )
        }
    }

    @ExceptionHandler(DataIntegrityViolationException::class)
    fun handleDataIntegrity(e: DataIntegrityViolationException):
            ResponseEntity<Map<String, String>> {
        return ResponseEntity
            .status(HttpStatus.CONFLICT)
            .body(
                mapOf(
                    "error" to "Duplicate value"
                )
            )
    }
}