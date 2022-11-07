package com.neosoft.springbootsecurityoauth2.auth;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.neosoft.springbootsecurityoauth2.security.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

    private PasswordEncoder  passwordEncoder;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser>  getApplicationUsers(){
        List<ApplicationUser>  applicationUser = Lists.newArrayList(

               new ApplicationUser(
                       "Motilal",
                       passwordEncoder.encode("12345"),
                       STUDENT.getGrantedAuthorities(),
                       true,
                       true,
                       true,
                       true

               ),

                new ApplicationUser(
                        "raja",
                        passwordEncoder.encode("12345"),
                        ADMIN.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true

                ),

                new ApplicationUser(
                        "venk",
                        passwordEncoder.encode("12345"),
                        ADMINTRAINEE.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true

                )


        );
        return applicationUser;
    }
}
