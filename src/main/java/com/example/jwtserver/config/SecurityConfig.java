package com.example.jwtserver.config;

import com.example.jwtserver.filter.MyFilter1;
import com.example.jwtserver.filter.MyFilter3;
import com.example.jwtserver.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;

    @Bean
    public BCryptPasswordEncoder encodePwd(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.addFilterBefore(new MyFilter3(), BasicAuthenticationFilter.class);
        //BasicAuthenticationFilter before 필터를 걸러줘라.
        //그냥 security와 상관없이 필터 걸수도 있음. FilterConfig
        // filter 3 - > filter 1 - > filter 2
        // security filter 먼저 실행 후에 filterconfig에 필터가 실행된다.

        //가장 빨리 필터 실행하세요!
        http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);
        http.addFilter(new JwtAuthenticationFilter(authenticationManager())); //전달해야하는 파라미터 있음. AuthenticationManager, WebSecurityConfigurerAdapter가 줌
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            //세션 사용하지 않음
            .and()
            .addFilter(corsFilter)
            .formLogin().disable()
                //폼 로그인 사용하지 않음
            .httpBasic().disable()
                // 클라이언트가 ID, PW로 최초 로그인 요청하면
                // 서버는 세션 메모리 영역 만들어서 세션 ID 만듬. 그리고 돌려줌
                // 클라이언트는 쿠키영역에 세션ID 저장함. SESSIONID
                // 요청할 때 쿠키 같이 날려서. SESSIONID 보고 확인
                // 서버가 여러 개가 될 경우 SESSION 메모리 관리하기 꾸짐.
                // redis 서버 비용 추가로 지출해야함
                // + 동일 도메인에서 요청할 때만 사용 가능함 (javascript 요청 쿠키 안 날라감...)
                // http only 라서 그렇다.
                // 강제로 쿠키를 담아서 요청할 수는 있음.
                // 그 말은? spa 사용하면 세션사용이 어려울 수 있겠군요.
                // 그렇다고 http only 를 false 로 하면? 보안에 안 좋음..

                // 그래서 headers Authorization: ID, PW 요청.
                // -> http basic 방식
                // id, pw 노출될 수 있음.
                // 그래서 https 써서 id, pw 암호화해서 사용함
                // 우리는 authorization: 토큰, 넣는 방식을 사용할 예정
                // 토큰 달고 요청하는 방식 bearer 방식
            .authorizeRequests()
            .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
            .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER')")
            .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_USER')")
            .anyRequest().permitAll();
//                .and()
//                .formLogin()
//                .loginProcessingUrl("/login") //default값인데.. 지금 disabled사용중 -> login요청 동작안해
//  -> jwtAuthenticationFilter 생성

    }
}
