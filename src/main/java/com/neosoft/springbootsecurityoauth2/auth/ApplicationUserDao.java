package com.neosoft.springbootsecurityoauth2.auth;

import com.neosoft.springbootsecurityoauth2.auth.ApplicationUser;

import java.util.Optional;

public interface ApplicationUserDao {

    Optional<ApplicationUser>  selectApplicationUserByUsername(String username);
}
