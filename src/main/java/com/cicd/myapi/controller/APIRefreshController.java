package com.cicd.myapi.controller;

import com.cicd.myapi.util.CustomJWTException;
import com.cicd.myapi.util.JWTUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;
import java.util.Map;

@RestController
@Slf4j
public class APIRefreshController {

    @RequestMapping("/api/member/refresh")
    public Map<String, Object> refresh(@RequestHeader("Authorization") String authHeader, String refreshToken) {
        // 헤더 Authorization 필요 -> AccessToken
        // 파라미터 -> RefreshToken
        log.info("************* APIRefreshController.java / method name : refresh / authHeader : {}", authHeader);
        log.info("************* APIRefreshController.java / method name : refresh / refreshToken : {}", refreshToken);
        
        // refresh token 이 없는 경우
        if(refreshToken == null) {
            throw new CustomJWTException("NULL_REFRESH_TOKEN");
        }
        // 헤더값이 맞지 않을 경우'
        if(authHeader == null || authHeader.length() < 7){
            throw new CustomJWTException("INVALID_STRING");
        }

        String accessToken = authHeader.substring(7);
        // Access Token이 만료되지 않은 경우
        if(checkExpriedToken(accessToken)){
            return Map.of("accessToken", accessToken, "refreshToken", refreshToken);
        }
        
        // 이 밑으로는 Access Token이 만료된 시점
        
        // Refresh Token 검증 -> claims 받기
        Map<String, Object> claims = JWTUtil.validateToken(refreshToken);
        log.info("************* APIRefreshController.java / method name : refresh / claims : {}", claims);
        
        // 새 토큰 생성해서 전달
        String newAccessToken = JWTUtil.generateToken(claims, 10);
        String newRefreshToken = checkRemainTime((Integer)claims.get("exp"))
                ? JWTUtil.generateToken(claims, 60 * 24)
                : refreshToken; // refresh 토큰 1시간이 안남았으면 새로 생성, 아니면 쓰던거 사용
        return Map.of("accessToken", newAccessToken, "refreshToken", newRefreshToken);
    }

    private boolean checkRemainTime(Integer exp) {
        Date expDate = new Date((long) exp * 1000);
        long diff = expDate.getTime() - System.currentTimeMillis();
        long diffMin = diff / (1000 * 60);
        return diffMin < 60; // 1시간 미만이면 true, 1시간 이상 남으면 false
    }

    // 토큰 만료 여부 확인 메서드 : 만료 == true / 만료 x == false
    private boolean checkExpriedToken(String accessToken) {
        try{
            JWTUtil.validateToken(accessToken); // 문제 생기면 예외 발생
        }catch (CustomJWTException e) {
            if(e.getMessage().equals("Expired")){
                return true;
            }
        }
        return false; // 그 외는 만료 x
    }
}
