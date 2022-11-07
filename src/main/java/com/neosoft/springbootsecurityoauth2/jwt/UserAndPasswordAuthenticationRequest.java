package com.neosoft.springbootsecurityoauth2.jwt;

public class UserAndPasswordAuthenticationRequest {

    private String username;
    private String password;

    public UserAndPasswordAuthenticationRequest() {

    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
