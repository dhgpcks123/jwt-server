package com.example.jwtserver.jwt;

import com.example.jwtserver.auth.PrincipalDetails;
import com.example.jwtserver.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;

// 스프링 시큐리티 UsernamePasswordAuthenticationFilter가 있음
// login 요청 하면 해당 필터 동작.
// loginForm .disable()하고 있어서 동작 안해서 임의로 작동 시켜 주려고 함
// security config에 등록

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    //login 요청을 하면 로그인 시도를 위해서 실해오디는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        System.out.println("JwtAuthenticationFilter.attemptAuthentication: 로그인 시도중");
        //1. username, password 받아서
        try {
//            BufferedReader bufferedReader = request.getReader();
//            String input = null;
//            while((input = bufferedReader.readLine())!=null){
//                System.out.println(input);
                //raw
                //webclient
                //android
//            }
            //json 으로 처리한다고 하고 파싱해보죠
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);
            //form로그인 시 자동으로 ㅌ큰 만들어주는데 우린 그거 안 쓰니까 만들어야됨

            UsernamePasswordAuthenticationToken authenticationToken
                    = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            //PrincipalDetailsService- loadUserByUsername() 함수가 실행됨
            // DB에 있는 username과 passowrd 일치한다.
            Authentication authentication
                    = authenticationManager.authenticate(authenticationToken);
            // 여기 authentication에 뭐가 담기는가?
            // 꺼내보자.
            //authentication 객체가 session영역에 저장됨
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println(principalDetails.getUser().getUsername());
            System.out.println(principalDetails.getUser().getPassword());
            // Principal r뿌릴 수 있다? 세션에 값 들어가서 로그인 됐다.

            // 이 authentication 이제 세션에 저장이 되어야 하고 그 방법이 return 해주면 됨
            // 리턴 이유는 권한 관리를 security가 대신 해주기 떄문에 편하려고 하는 거임
            // 굳이 jwt 토큰 쓰는데 세션 만든 이유? 권한 처리 때문에 session 넣어줌
            return authentication;

        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("=============================");

        return null;
    }


    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);
    }
}
