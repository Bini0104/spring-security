package com.ohgiraffers.sessionsecurity.config;

import com.ohgiraffers.sessionsecurity.common.UserRole;
import com.ohgiraffers.sessionsecurity.config.handler.AuthFailHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private AuthFailHandler authFailHandler;

    /* 비밀번호 암호화에 사용할 객체 BCryptPasswordEncoder bean 등록 */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /* 정적 리소스에 대한 요청은 제외하는 설정 */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        /* 요청에 대한 권한 체크 */
             // 인가 설정           // 인가를 전달 받아서
        http.authorizeHttpRequests( auth -> {
                                  // 로그인 하지 않아도 볼 수 있는 페이지들                               - 허용해주겠다.
            auth.requestMatchers("/auth/login", "/user/signup", "/auth/fail", "/", "/main").permitAll();
            // 관리자, user 가 맞다면
            auth.requestMatchers("/admin/*").hasAnyAuthority(UserRole.ADMIN.getRole());
            auth.requestMatchers("/user/*").hasAnyAuthority(UserRole.USER.getRole());
            auth.anyRequest().authenticated();

        }).formLogin( login -> {
            login.loginPage("/auth/login");

            // 로그인 html 이름 속성과 맞으면
            login.usernameParameter("user");
            login.passwordParameter("pass");

            login.defaultSuccessUrl("/", true);
            login.failureHandler(authFailHandler);

        }).logout( logout -> {
            logout.logoutRequestMatcher(new AntPathRequestMatcher("/auth/logout"));
            // 쿠키 지우기
            logout.deleteCookies("JSESSIONID");
            logout.invalidateHttpSession(true);
            logout.logoutSuccessUrl("/");

        }).sessionManagement( session -> {
            // 세션을 1개 허용
            session.maximumSessions(1);
            // 만료되면 루트로 이동
            session.invalidSessionUrl("/");
                            // 개발 할 때 권한을 잠깐 풀어두고 하는 것이 좋다.
        }).csrf( csrf -> csrf.disable());

        return http.build();
    }
}