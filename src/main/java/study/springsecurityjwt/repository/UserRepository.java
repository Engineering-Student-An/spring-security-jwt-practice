package study.springsecurityjwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import study.springsecurityjwt.entity.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    boolean existsByUsername(String username);

    UserEntity findByUsername(String username);
}
