package com.evecta.auth.model;


public enum UserRole {

    USER_APP("fiscalizador"),
    USER_ADMIN("administrador"),
    USER_JPL("JPL"),
    USER_SUPERVISOR("supervisor");

    private final String description;

    UserRole(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}