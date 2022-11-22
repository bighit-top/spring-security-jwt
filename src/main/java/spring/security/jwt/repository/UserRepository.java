package spring.security.jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import spring.security.jwt.model.User;

public interface UserRepository extends JpaRepository<User, Long> {
    public User findByUsername(String username);
}
