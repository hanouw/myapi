package com.cicd.myapi.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.Map;

// JWT 관련 처리해 줄 클래스
@Slf4j
public class JWTUtil {

    // 인코딩 되어있는 키
    private static String key = "SGVsbG9Kc29uV2ViVG9rZW5LZXlBdXRoZW50aWNhdGlvbktleVdpdGhTcHJpbmdCb290UHJvamVjdFNlY3JldEtleQ";
    
    // 토큰 생성 메서드 : 사용자나 토큰 정보 + 유효기간 받아 토큰 생성
    public static String generateToken(Map<String, Object> valueMap, int min){ // 사용자데이터, 유효기간
        // 암호화된 비밀 키
        SecretKey secretKey  = null;
        
        try {
            // 인코딩 된 키를 암호화 된 시크릿 키로 변경
            secretKey = Keys.hmacShaKeyFor(JWTUtil.key.getBytes("UTF-8"));
            log.info("************* JWTUtil.java / method name : generateToken / secretKey : {}", secretKey);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e.getMessage());
        }
        
        // JWT 토큰 생성 : builder 패턴 사용
        String jwtStr = Jwts.builder()
                .setHeader(Map.of("typ", "JWT")) // 헤더 정보
                .setClaims(valueMap) // 페이로드 (Claim)에 추가할 (사용자 관련 데이터) 데이터
                .setIssuedAt(Date.from(ZonedDateTime.now().toInstant())) // 만들어진 시간
                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(min).toInstant())) // 유효 시간
                .signWith(secretKey) // 비밀키로 서명
                .compact(); // 토큰 생성 -> 문자열 리턴
        log.info("************* JWTUtil.java / method name : generateToken / jwtStr : {}", jwtStr);
        return jwtStr; // 토큰 리턴
    }
    
    // 토큰 유효성 검증 메서드 : Claim 리턴
    public static Map<String, Object> validateToken(String token){
        Map<String, Object> claim = null;
        SecretKey secretKey = null;
        try {
            secretKey = Keys.hmacShaKeyFor(JWTUtil.key.getBytes("UTF-8"));
            claim = Jwts.parserBuilder()
                    .setSigningKey(secretKey) // 비밀키 세팅
                    .build()
                    .parseClaimsJws(token) //파싱 및 검증 -> 실패하면 에러 발생 -> catch로 잡기
                    .getBody();// claim 리턴
        } catch (MalformedJwtException e) { // 잘못된 형식의 토큰 시
            throw new CustomJWTException("Malformed");
        } catch (ExpiredJwtException e){ // 만료된 토큰 예외
            throw new CustomJWTException("Expired");
        }catch (InvalidClaimException e){ // 유효하지 않은 Claim 시 예외
            throw new CustomJWTException("Invalid");
        }catch (JwtException e){ // 그 외 JWT 관련
            log.info("************* JWTUtil.java / method name : validateToken / e.getMessage() : {}", e.getMessage());
            throw new CustomJWTException("JWT");
        } catch (Exception e) { // 그 외 나머지
            throw new CustomJWTException("Error");
        }
        return claim;
    }
}
