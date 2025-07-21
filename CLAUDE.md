# Claude Spring Boot 개발 가이드라인

## 기본 원칙
• 항상 한글로 답변해줘
• 모든 답변은 나를 '서진님' 호칭을 하고 상냥한 조선시대 처지의 존대말을 사용
• 사용자가 오류를 첨부시 연쇄적 사고로 먼저 핵심 문제를 찾고 단계별로 해결 방안을 계획하세요
• 전체 파일을 다시 작성하는 것보다 차이점만 수정(diff 기반 수정)을 우선으로 해

## Spring Boot 개발 규칙
• Spring Boot 3.x 버전 기준으로 개발
• JPA/Hibernate를 사용한 데이터베이스 연동
• RESTful API 설계 원칙 준수
• Controller, Service, Dto, Repository,Entity 등 패키지를 만들어서 구현
• Spring Security를 활용한 인증/인가 구현
• 프론트엔드는 react 사용


## 테스트 및 개발 방식
• 완결된 하나의 작업이 끝나면 커밋할지 물어봐
• JUnit 5와 Spring Boot Test를 사용한 테스트 작성
• 개발 또는 수정을 요청받았을 때 테스트를 먼저 만드는 TDD(Test Driven Development) 방식으로 개발할지 물어봐 줘
• 개발 또는 수정이 완료되면 `./gradlew test` 또는 `mvn test` 명령을 통해 테스트를 할지 물어 봐
• @SpringBootTest, @WebMvcTest, @DataJpaTest 등 적절한 테스트 슬라이스 활용
• 테스트 데이터는 @Sql 어노테이션이나 테스트용 데이터 설정 사용

## 프로젝트 구조
• 계층형 아키텍처 (Controller → Service → Repository)
• DTO 패턴을 활용한 데이터 전송
• 적절한 예외 처리 및 에러 핸들링
• 설정 파일은 application.properties우선 사용
• 패키지 구조는 기능별로 구성

## 데이터베이스 및 JPA
• Entity 설계 시 적절한 연관관계 설정
-spring data jpa
• JPQL, Criteria API, Native Query 적절히 활용
• N+1 문제 등 성능 이슈 고려
• 트랜잭션 관리 (@Transactional) 적절히 활용

## 웹 개발
• http://localhost:8080 으로 접속해서 서버 확인
• 로그는 logback 설정을 통해 확인
• 네이버 스타일의 기본 디자인 적용
• tailwind 활용

## 커밋 및 배포
• 커밋할 땐 항상 빌드가 잘 되는 상태여야 하고 테스트가 통과하는 상태여야 해
• Git 커밋 메시지는 Conventional Commits 형식 사용
• 배포 전 반드시 전체 테스트 실행 및 통과 확인

## 보안 및 성능
• Spring Security 설정을 통한 보안 강화
• SQL Injection, XSS 등 보안 취약점 방지
• 캐싱 전략 적절히 활용
• 데이터베이스 인덱스 및 쿼리 최적화 고려