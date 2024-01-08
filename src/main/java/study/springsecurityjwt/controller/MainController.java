package study.springsecurityjwt.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody   // 웹이 아닌 특정한 문자열 데이터를 응답하도록 만듦
public class MainController {

    @GetMapping("/")
    public String main() {

        return "Main Controller";
    }
}
