package spring.security.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import spring.security.jwt.config.auth.PrincipalDetails;
import spring.security.jwt.model.User;
import spring.security.jwt.repository.UserRepository;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 시큐리티가 filter 를 가지고 있는데 그 필터중에 BasicAuthenticationFilter 라는 것이 있다
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 거친다
// 만약 권한이나 인증이 필요한 주소가 아니라면 이 필터를 거치지 않는다
@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    // 인증, 권한이 필요한 주소요청이 있을 경우 해당 필터를 거침
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {

        log.info("인증, 권한이 필요한 주소 요청");

        // header 의 authorization 토큰 확인
        String authorization = request.getHeader("Authorization");
        log.info("authorization: {}", authorization);

        if (authorization == null || !authorization.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
        }

        // jwt 토큰이 정상인지 확인
        String jwtToken = request.getHeader(JwtProperties.HEADER_STRING).replace(JwtProperties.TOKEN_PREFIX, "");
        String username = null;
        try {
            username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(jwtToken)
                    .getClaim("username").asString();
        } catch (JWTVerificationException e) {
            throw new JWTVerificationException("토큰 검증 오류");
        }

        // 사용자의 Authentication 객체 생성 후 시큐리티 세션에 강제 저장
        if (username != null) {
            User user = userRepository.findByUsername(username);
            PrincipalDetails principalDetails = new PrincipalDetails(user);
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(
                            principalDetails, //유저정보
                            null, //패스워드
                            principalDetails.getAuthorities() //권한
                    );
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        chain.doFilter(request, response);
    }
}
