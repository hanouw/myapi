package com.cicd.myapi.security.handler;

import com.cicd.myapi.dto.MemberUserDetail;
import com.cicd.myapi.util.JWTUtil;
import com.google.gson.Gson;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;

@Slf4j
public class CustomLoginSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("************* CustomLoginSuccessHandler.java / method name : onAuthenticationSuccess / request : {}", request);

        // 로그인 성정 -> JSON 문자열로 응답해줄 데이터 생성 -> 응답 *
        // 응답 데이터 생성 -> 사용자 정보
        MemberUserDetail memberUserDetail = (MemberUserDetail) authentication.getPrincipal();
        Map<String, Object> claims = memberUserDetail.getClaims();// 사용자 정보 Map 타입으로 변환

        // 10분짜리 JWT 토큰 생성
        String accessToken = JWTUtil.generateToken(claims, 10);
        String refreshToken = JWTUtil.generateToken(claims, 60 * 24); // 24시간

        claims.put("accessToken", accessToken);
        claims.put("refreshToken", refreshToken); // 추후 JWT 할 때 수정. 일단 빈문자열로 처리

        // 위 응답 데이터를 JSON 문자열로 변환
        Gson gson = new Gson();
        String jsonStr = gson.toJson(claims);

        // 응답하기
        response.setContentType("application/json; charset=UTF-8"); // 응답 데이터 형태 헤더정보 추가
        PrintWriter writer = response.getWriter();
        writer.println(jsonStr);
        writer.close();
        
    }
}
