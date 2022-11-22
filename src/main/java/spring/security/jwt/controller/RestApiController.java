package spring.security.jwt.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import spring.security.jwt.model.User;
import spring.security.jwt.repository.UserRepository;

@RequiredArgsConstructor
@RestController
public class RestApiController {

    @Autowired
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private final UserRepository userRepository;

    @GetMapping("/home")
    public String home() {
        return "<h1>home</h1>";
    }

    @PostMapping("/token")
    public String token() {
        return "<h1>token</h1>";
    }

    @PostMapping("/join")
    public String join(@RequestBody User user) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "회원가입 완료";
    }

    // 권한: user, manager, admin
    @GetMapping("/api/v1/user")
    public String user() {
        return "user";
    }

    // 권한: manager, admin
    @GetMapping("/api/v1/manager")
    public String manager() {
        return "manager";
    }

    // 권한: admin
    @GetMapping("/api/v1/admin")
    public String admin() {
        return "admin";
    }
}
