package com.neosoft.springbootsecurityoauth2.security;

import com.neosoft.springbootsecurityoauth2.auth.ApplicationUserService;
import com.neosoft.springbootsecurityoauth2.jwt.JwtConfig;
import com.neosoft.springbootsecurityoauth2.jwt.JwtTokenVerifier;
import com.neosoft.springbootsecurityoauth2.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import javax.crypto.SecretKey;

import static com.neosoft.springbootsecurityoauth2.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;
    private final ApplicationUserService  applicationUserService;
    private final PasswordEncoder passwordEncoder;


    @Autowired
    public ApplicationSecurityConfig(SecretKey secretKey,
                                     JwtConfig jwtConfig,
                                     ApplicationUserService applicationUserService,
                                     PasswordEncoder passwordEncoder) {
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
        this.applicationUserService = applicationUserService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http

               // .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                //.and()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
                .addFilterAfter(new JwtTokenVerifier(secretKey, jwtConfig), JwtUsernameAndPasswordAuthenticationFilter.class)
                .authorizeHttpRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .anyRequest()
                .authenticated();
               /* .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                .antMatchers("/management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ADMINTRAINEE.name())
*/
                /*.and()
                .formLogin()
                    .loginPage("/login")
                    .permitAll()
                    .defaultSuccessUrl("/courses", true)
                    .passwordParameter("password")
                    .usernameParameter("username")
                .and()
                .rememberMe()
                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))     // Default to two weeks
                    .key("Somethingverysecured")
                    .rememberMeParameter("remember-me")
                .and()
                .logout()
                .logoutUrl("/logout")
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID", "remember-me")
                .logoutSuccessUrl("/login");*/
                //.httpBasic();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        auth.authenticationProvider(daoAuthenticationProvider());

    }

    @Bean
    public DaoAuthenticationProvider  daoAuthenticationProvider(){

        DaoAuthenticationProvider  provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);

        return provider;
    }





    protected UserDetailsService userDetailsService() {
        UserDetails motilalUser = User.builder()
                .username("Motilal")
                .password(passwordEncoder.encode("12345"))
                //.roles(ApplicationUserRole.STUDENT.name())          //ROLE_STUDENT
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

       UserDetails rajaUser =  User.builder().username("raja")
                .password(passwordEncoder.encode("r12345"))
               // .roles(ApplicationUserRole.ADMIN.name())             //ROLE_ADMIN
               .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails VenkUser =  User.builder().username("venk")
                .password(passwordEncoder.encode("r12345"))
               // .roles(ApplicationUserRole.ADMINTRAINEE.name())        //ROLE_ADMINTRAINEE
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build();

        return  new InMemoryUserDetailsManager(
                motilalUser,
                rajaUser,
                VenkUser
        );
    }
}
