package spring.security.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import spring.security.jwt.config.auth.PrincipalDetails;
import spring.security.jwt.model.User;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter 가 있음
// /login 요청시 POST username,password 가 넘어오면 해당 필터가 동작함
// formLogin().disabled() 했을 경우 동작하지 않으므로
// 필터를 새로 추가해주면 됨 : apply(AuthenticationManager)
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // login 요청을 하면 로그인 시도를 위해 실행되는 함수
    // 1. username, password 를 받아서
    // 2. 정상인지 시도
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        log.info("로그인 시도");

        // 1. username, password 를 받아서
        ObjectMapper om = new ObjectMapper();
        User user = null;
        try {
            user = om.readValue(request.getInputStream(), User.class);
            log.info("user: {}",user);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // 유저네임패스워드 토큰 생성
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

        log.info("token: {}", authenticationToken);

        // 2. 정상인지 시도
        // authenticationManager 로 로그인을 시도하면
        // PrincipalDetailsService 의 loadUserByUsername() 함수가 실행되고
        // db와 일치해서 정상이면 authentication 이 리턴됨
        Authentication authentication =
                authenticationManager.authenticate(authenticationToken); //로그인 정보가 담김

        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        log.info("로그인 완료 PrincipalDetails: {}", principalDetails.getUser().getUsername());

        return authentication;
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수 실행
    // JWT 토큰을 만들어서 request 요청 클라이언트에게 response 해줌
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult) throws IOException, ServletException {

        log.info("successfulAuthentication 실행");

        // 3. PrincipalDetails 를 세션에 담고 (=권한 처리)
        // authentication 객체가 session 영역에 저장됨 => 로그인 완료
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // 4. JWT 토큰을 만들어서 응답
        // Hash 암호방식 (RSA 방식 X)
        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX+jwtToken);
    }
}
