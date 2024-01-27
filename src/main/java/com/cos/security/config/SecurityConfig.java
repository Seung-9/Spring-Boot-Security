package com.cos.security.config;

import com.cos.security.config.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록
// secure 활성화 하는 것임. @Secured 어노테이션을 달아주면 간단하게 role을 부여할 수 있음, prePostEnable은 디폴트 값이 true임
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    @Bean
    protected SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .requestMatchers("/user/**").authenticated() // 인증만 되면 들어갈 수 있음
                .requestMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .requestMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin().loginPage("/loginForm")
                .loginProcessingUrl("/login") // 시큐리티가 /login 을 낚아채서 로그인을 진행 시킴
                .defaultSuccessUrl("/")
                .and()
                .oauth2Login().loginPage("/loginForm")
                // 이제 구글 로그인이 완료 된 후의 후처리를 해야됨 ( 코드를 받는 게 아니라, 엑세스 토큰 + 사용자 프로필 정보를 받아오는 것 )
                .userInfoEndpoint()
                .userService(principalOauth2UserService);

        return http.build();
    }
}
