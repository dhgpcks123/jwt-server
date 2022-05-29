package com.example.jwtserver.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
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
import java.util.Date;

// 스프링 시큐리티 UsernamePasswordAuthenticationFilter가 있음
// login 요청 하면 해당 필터 동작.
// loginForm .disable()하고 있어서 동작 안해서 임의로 작동 시켜 주려고 함
// security config에 등록

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    //login 요청을 하면 로그인 시도를 위해서 실행하는 메서드
    // attempt Authentication
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
            //form로그인 시 자동으로 토큰 만들어주는데 우린 그거 안 쓰니까 만들어야됨

            UsernamePasswordAuthenticationToken authenticationToken
                    = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());


            //PrincipalDetailsService- loadUserByUsername() 함수가 실행됨
            // DB에 있는 username과 passowrd 일치한다.
            // loadUserByUsername() 메서드 실행하고 이거 return 되어서 받은 값임.
            Authentication authentication
                    = authenticationManager.authenticate(authenticationToken);
            // 여기 authentication에 뭐가 담기는가?
            // 꺼내보자.
            //authentication 객체가 session영역에 저장됨
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료 됨"+principalDetails.getUser().getUsername());
            System.out.println(principalDetails.getUser().getPassword());
            // Principal r뿌릴 수 있다? 세션에 값 들어가서 로그인 됐다.

            // 이 authentication 이제 세션에 저장이 되어야 하고 그 방법이 return 해주면 됨
            // 리턴 이유는 권한 관리를 security가 대신 해주기 떄문에 편하려고 하는 거임
            // 굳이 jwt 토큰 쓰는데 세션 만든 이유? 권한 처리 때문에 session 넣어줌
            return authentication;
            // 만약 attempAuthentication에서 권한처리 안할거면 세션 만들 이유없음.
            // 리턴은 그대로 하고 시큐리티 세션에 안 담으면 된다.
            // securityContextHolder
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("=============================");

        return null;
    }


    // attemptAuthentication 실행 후 인증 정상? -> successful Authentication
    // 로그인 인증 성공!
    // JWT 토큰 만들어서 request 요청한 사용자에게 JWT 토큰 response 해줍니다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("JwtAuthenticationFilter.successfulAuthentication : 인증이 완료되었음!");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // JWT 토큰 생성 빌드 패턴으로
        // hash 암호화 방식임
        // secret 키를 서버가 가지고 있음
        String jwtToken = JWT.create()
                .withSubject("jwtToken")
                // 만료 시간, 탈취되어도 로그인 시도 못하도록
//                .withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.))
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))//1분*10 = 10분
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                // 비공개 Claim. 넣고싶은 거 넣으면 됨. id만 넣어도 될 듯
//                .sign(Algorithm.HMAC256(JwtProperties.SECRET))
                .sign(Algorithm.HMAC512("cos"));


        //일반적으로 서버쪽 세션ID
        //클라이언트 쿠키 세션 ID 응답
        // 요청 때 마다 쿠키값 세션 ID를 항상 들고 서버쪽 요청
        // 서버는 세션 ID 유효한지 판단, 인증하고 페이지로 접근
//        session.getAttribute("세션 값 확인");

        // -> 우린 이제 JWT 토큰 생성해서
        // 클라이언트 쪽으로 JWT 토큰 응답, 요청할 때 마다 JWT토큰 가지고 요청
        // 서버는 JWT 토큰이 유효한지 판단이 필요함. 필터를 만들어야함
        response.addHeader("Authorization", "Bearer "+jwtToken);

        /*

메타코딩
1년 전
제 깃에 있어요 ㅎ
https://github.com/codingspecialist/Springboot-Oauth2.0-Facebook-Google-Login-JWT

만약에리엑트쪽 연동원하면
https://github.com/codingspecialist/Springboot-JWT-React-OAuth2.0-Eazy



         */
    }
}
