package com.springmvc.config;

import com.springmvc.handler.LoginSuccessHandler;
import com.springmvc.handler.LogoutSuccessHandler;
import com.springmvc.service.CustomUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.sql.DataSource;

@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {


    @Autowired
    LoginSuccessHandler loginSuccessHandler;

    @Autowired
    LogoutSuccessHandler logoutSuccessHandler;

    @Autowired
    CustomUserDetailService customUserDetailService;

    @Autowired
    DataSource dataSource;

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder managerBuilder) throws Exception {
        managerBuilder
                .userDetailsService(customUserDetailService);

    }

    /*@Autowired
    public void configureGlobal(AuthenticationManagerBuilder managerBuilder) throws Exception {
        managerBuilder
                .inMemoryAuthentication()
                .withUser("nitesh").password("pass").roles("USER")
                .and()
                .withUser("user2").password("pass2").roles("ADMIN");

    }*/

    /*@Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/home/**").hasAuthority("ROLE_USER")
                .anyRequest().authenticated()
                .and()
                .formLogin();
    }*/

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf()
                .disable()
                .authorizeRequests()
                .antMatchers("/register/**").permitAll()
                .antMatchers("/registerUser/**").permitAll()
                .antMatchers("/registrationConfirmation/**").permitAll()
                .anyRequest().authenticated()
                .and().formLogin()
                .successHandler(loginSuccessHandler)
                .loginPage("/login").permitAll()
                .loginProcessingUrl("/loginUrl")

                .and()
                .rememberMe()
                .tokenRepository(persistentTokenRepository())
                .and()
                .logout()
                .permitAll()
                .logoutRequestMatcher(new AntPathRequestMatcher("/doLogout", "GET"))
                .logoutSuccessHandler(logoutSuccessHandler);
    }


    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        return jdbcTokenRepository;
    }
}
