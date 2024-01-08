package study.springsecurityjwt.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import study.springsecurityjwt.jwt.JWTFilter;
import study.springsecurityjwt.jwt.JWTUtil;
import study.springsecurityjwt.jwt.LoginFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    // AuthenticationManager가 인자로 받을 AuthenticationConfiguration 객체, JWTUtil
    private final AuthenticationConfiguration configuration;
    private final JWTUtil jwtUtil;

    // AuthenticationManager Bean 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // csrf disable 설정
        // 세션 방식 : 세션이 고정 => csrf 공격을 필수적으로 방어해야함
        // JWT 방식 : 세션을 stateless 방식으로 관리 => csrf 공격 방어 필요 x
        http.
                csrf( (auth) -> auth.disable());

        // form 로그인 방식 disable 설정
        http
                .formLogin((auth) -> auth.disable());

        // http basic 인증 방식 disable 설정
        http
                .httpBasic((auth) -> auth.disable());

        // 경로별 인가 작업
        http
                .authorizeHttpRequests( (auth) -> auth
                        .requestMatchers("/","/login","/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated());

        // 세션 설정 (*****중요***** JWT에서는 세션을 항상 stateless 상태로 관리함 => 이를 위한 설정)
        http
                .sessionManagement( (session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // 필터 등록 (UsernamePasswordAuthenticationFilter 자리에 (대신에) 생성한 LoginFilter를 등록)
        // addFilter => At : 원하는 자리에 등록
        //              Before : 특정 필터 이전에 등록
        //              After : 특정 필터 이후에 등록
        http
                .addFilterAt(new LoginFilter(authenticationManager(configuration), jwtUtil), UsernamePasswordAuthenticationFilter.class);

        // JWT 검증 필터 등록
        http
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);

        return http.build();
    }

    // BCryptPasswordEncoder 등록
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }
}
