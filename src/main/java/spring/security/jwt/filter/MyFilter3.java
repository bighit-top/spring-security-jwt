package spring.security.jwt.filter;

import lombok.extern.slf4j.Slf4j;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
                         FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        // 토큰이 있을 때 : cos
        // id,pw 가 정상으로 입력되어 로그인이 완료되면 토큰을 만들어주고 토큰을 응답해준다
        // 클라이언트에서 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지 검증한다 (RSA,SH256)
        if (request.getMethod().equals("POST")) {

            log.info("POST 요청");

            String authorization = request.getHeader("Authorization");

            log.info("Authorization: {}" + authorization);
            log.info("필터3");

            if (authorization.equals("cos")) {
                filterChain.doFilter(servletRequest, servletResponse);
            } else {
                PrintWriter out = response.getWriter();
                out.println("인증 안됨");
            }
        }

    }
}
