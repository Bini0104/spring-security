package com.ohgiraffers.sessionsecurity.common;
// enum 열거, 상수의 집합, 클래스의 일종


public enum UserRole {

    USER("USER"),
    ADMIN("ADMIN");

    private String role;

    UserRole(String role){
        this.role = role;
    }

    public String getRole(){
        return role;
    }

    @Override
    public String toString() {
        return "UserRole{" +
                "role='" + role + '\'' +
                '}';
    }
}
