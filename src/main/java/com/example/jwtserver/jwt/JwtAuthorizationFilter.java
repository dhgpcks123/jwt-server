package com.example.jwtserver.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwtserver.auth.PrincipalDetails;
import com.example.jwtserver.model.User;
import com.example.jwtserver.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.Principal;

/*
    시큐리티가 filter를 가지고 있는데 그 필터중에 BasicAuthenticationFilter라는 것이 있다.
    권한이나 인증이 필요한 특정 주소를 요청했을 때 이 필터를 무조건 타게 되어있음
    만약에 권한 인증이 필요한 주소가 아니라면 이 필터를 안 타요.
 */
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final UserRepository userRepository;
    private final HttpSession session;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository, HttpSession session) {
        super(authenticationManager);
        this.userRepository = userRepository;
        this.session = session;
    }

    //인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게 됨.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println(" 인증이나 권한이 필요한 요청 JwtAuthorizationFilter.JwtAuthorizationFilter");


        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader : "+jwtHeader);
        //        jwtHeader : cos
        // jwtHeader 토큰을 검증해서 정상적인 사용자인지 확인
        //header가 있는지 확인
        if(jwtHeader == null || !jwtHeader.startsWith("Bearer")){
            chain.doFilter(request, response);
            return;
        }
        //JWT 토큰을 검증해서 정상적인 사용자인지 확인
        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");
        String username = JWT.require(Algorithm.HMAC512("cos")).build().verify(jwtToken).getClaim("username").asString();
        String userId = JWT.require(Algorithm.HMAC512("cos")).build().verify(jwtToken).getClaim("id").asString();
        //

        // 서명이 정상적으로 됨
        if (username != null) {

            // 1. authenticationManager.authenticate() 함수를 타게 되면 인증을 한번 더 하게 되고
            // 이때 비밀번호 검증을 하게 되는데, User 테이블에서 가져온 비밀번호 해시값으로 비교가 불가능하다.
            // 2. 그래서 강제로 세션에 저장만 한다.
            // 3. 단점은 @AuthenticationPrincipal 어노테이션을 사용하지 못하는 것이다.
            // 4. 이유는 UserDetailsService를 타지 않으면 @AuthenticationPrincipal 이 만들어지지 않는다.
            // 5. 그래서 @LoginUser 을 하나 만들려고 한다.
            // 6. 그러므로 모든 곳에서 @AuthenticationPrincipal 사용을 금지한다. @LoginUser 사용 추천!!

            System.out.println("여기 들어있는 username은 ?"+username);
            User user = userRepository.findByUsername(username);

//            PrincipalDetails principalDetails = new PrincipalDetails(user);

            // jwt 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다.
//            Authentication authentication
//                    = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
            //로그인 x princidpalDetails넣고, null(ㅠㅐ스워드) 넣고

            // 강제로 시큐리티 세션에 접근해서 Authentication 객체를 저장
//            SecurityContextHolder.getContext().setAuthentication(authentication);

            PrincipalDetails principalDetails = new PrincipalDetails(user);
            session.setAttribute("principal", principalDetails);
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(
                            principalDetails, null, principalDetails.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(authentication);

        }
        chain.doFilter(request, response);
    }
}
