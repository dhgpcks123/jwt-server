package com.example.jwtserver.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
//        System.out.println("MyFilter33333.doFilter");

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

//        System.out.println("((HttpServletRequest) request).getMethod() = " + ((HttpServletRequest) request).getMethod());

        //  토큰 cos 넘어오면 인증 계속 진행, 아니면 끝!
        // 이제 토큰 : cos를 만들어줘야함. id, pw 정상적으롣 ㅡㄹ어와서 로그인 완료되면 토큰을 만들어주고 그걸 응답해준다.
        // 요청할 때 마다 header에 authoriztion에 value값으로 토큰 가지고 오겠죠?
        // 그럼 넘어온 토큰 내가 만든건지 인증하면 되겠죠? RSA
        //
//
        if(req.getMethod().equals("POST")){
            String headerAuth = req.getHeader("Authorization");
            System.out.println("header, Authoriztion에 담긴 값 " + headerAuth);
            if(headerAuth.equals("cos")){
                chain.doFilter(request, response);
            }else{
                PrintWriter out =res.getWriter();
                out.println("인증 안됨");
            }
        }


    }
}
