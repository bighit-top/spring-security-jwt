package spring.security.jwt.config.jwt;

public interface JwtProperties {
    String SECRET = "secretKey"; // 해당 서버의 시크릿 키
    int EXPIRATION_TIME = 60000; // 1분 (1/1000초)
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
}