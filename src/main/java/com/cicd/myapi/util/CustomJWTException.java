package com.cicd.myapi.util;

// JWT 부분에서 예외 발생하면 예외 정보 담아줄 예외 클래스 직접 구현
public class CustomJWTException extends RuntimeException{
    // 예외 클래스 생성자
    public CustomJWTException(String msg) {
        super(msg); // 예외 발생시 메세지 설정
    }
}
