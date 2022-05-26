package com.example.jwtserver.filter;

import javax.servlet.*;
import java.io.IOException;

public class MyFilter2 implements Filter {


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("MyFilter22222.doFilter");
        chain.doFilter(request, response);
    }
}
