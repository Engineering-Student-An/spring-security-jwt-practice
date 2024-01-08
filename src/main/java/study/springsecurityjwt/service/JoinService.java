package study.springsecurityjwt.service;

import lombok.RequiredArgsConstructor;
import org.apache.catalina.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import study.springsecurityjwt.dto.JoinDto;
import study.springsecurityjwt.entity.UserEntity;
import study.springsecurityjwt.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void joinProcess(JoinDto joinDto) {

        String username = joinDto.getUsername();
        String password = joinDto.getPassword();

        if(userRepository.existsByUsername(username)){
            // username이 이미 존재하면 강제 리턴 (회원가입x)
            return;
        }
        UserEntity userEntity = new UserEntity();

        userEntity.setUsername(username);
        // 비밀번호 암호화
        userEntity.setPassword(bCryptPasswordEncoder.encode(password));
        userEntity.setRole("ROLE_ADMIN");

        userRepository.save(userEntity);
    }
}
