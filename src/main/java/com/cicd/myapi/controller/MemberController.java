package com.cicd.myapi.controller;

import com.cicd.myapi.dto.MemberModifyDTO;
import com.cicd.myapi.dto.MemberUserDetail;
import com.cicd.myapi.service.MemberService;
import com.cicd.myapi.util.JWTUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;


@RestController
@Slf4j
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;

    // 테스트 메세지
    @GetMapping("/apitest")
    public String test(){
        return "test message";
    }

    @GetMapping("/api/member/kakao")
    public Map<String, Object> getMemberFromKakao(String accessToken) {
        log.info("**************SocialController-getMemberFromKakao - accessToken: {}", accessToken);

        MemberUserDetail kakaoMember = memberService.getKakaoMember(accessToken);
        Map<String, Object> claims = kakaoMember.getClaims();
        String jwtAccessToken = JWTUtil.generateToken(claims, 10);
        String jwtRefreshToken = JWTUtil.generateToken(claims, 60 * 24);
        claims.put("accessToken", jwtAccessToken);
        claims.put("refreshToken", jwtRefreshToken);

        return claims;
    }

    @PutMapping("/api/member/modify")
    public Map<String, String> modify(@RequestBody MemberModifyDTO memberModifyDTO){
        memberService.modifyMember(memberModifyDTO);
        return Map.of("result", "MODIFIED");
    }
}
