이 리포지토리는 JWT에 대한 개인적인 공부를 위해 사용하고 있습니다. 주로 JWT에 대해 공부한 내용이나 코드를 정리해서 올리고 있습니다.

# Table of Contents
- [정의](#정의)
- [작업 흐름](#작업-흐름)
- [토큰 탈취에 대한 대응 방안](#토큰-탈취에-대한-대응-방안)
  * [Access + Refresh Token을 이용한 인증](#access--refresh-token을-이용한-인증)
  * [RTR(Refresh Token Rotation)](#rtrrefresh-token-rotation)
- [스프링 부트 시큐리티](#스프링-부트-시큐리티)
  * [의존성 추가](#의존성-추가)
    + [Gradle](#gradle)
  * [시큐리티 설정](#시큐리티-설정)
- [참고](#참고)
 
# 정의
토큰 기반 인증 시스템은 로그인 시 토큰을 발급해주고, 서버에 요청을 할 때 HTTP 헤더에 토큰을 함께 보내도록 하여 유효성 검사를 하는 방식이다. 사용자의 인증 정보를 더 이상 서버에 저장하지 않고 클라이언트의 요청으로만 인가(authorization)를 처리할 수 있으므로 무상태(stateless) 구조를 가진다.

JWT는 JSON Web Token의 약자로, 인증에 필요한 정보를 암호화 시킨 토큰을 말한다. 세션/쿠키 방식과 유사하게 클라이언트는 `Access Token`을 HTTP 헤더에 실어서 서버로 보낸다.

# 작업 흐름
1. 사용자가 로그인을 한다.
2. 서버에서는 계정 정보를 읽어서 사용자를 확인 후, 사용자의 고유한 ID 값을 부여하고 페이로드에 정보를 넣는다.
3. JWT 토큰의 유효기간을 설정한다.
4. 개인키(secret key)를 통해서 암호화된 `Access Token`을 HTTP 응답 헤더에 실어 보낸다.
5. 사용자는 `Access Token`을 받아 저장한 후, 인증이 필요한 요청마다 토큰을 HTTP 요청에 실어서 보낸다.
6. 서버에서는 해당 토큰의 서명(verify signature)을 개인키로 복호화한 후, 조작 여부나 유효 기간을 확인한다.
7. 검증이 완료되면 페이로드를 디코딩하여 사용자의 ID에 맞는 데이터를 가져온다.

# 토큰 탈취에 대한 대응 방안
## Access + Refresh Token을 이용한 인증
`Access Token`을 이용한 인증 방식의 문제점은 해커에게 탈취당할 경우 보안에 취약하다는 점이다. 토큰의 유효기간을 짧게 하면 사용자는 로그인을 자주 해야해서 번거롭고, 길게 하면 보안이 취약해지기 때문에 이를 해결하고자 나온 것이 바로 `Refresh Token`이다.

`Refresh Token`은 `Access Token`과 같은 형태인 JWT이다. `Refresh Token`은 `Access Token`보다 긴 유효기간을 가지고, `Access Token`이 만료됐을 때 새로 발급해주는 열쇠가 된다. 예를 들어서, `Refresh Token`의 유효기간이 2주, `Access Token`의 유효기간이 1시간이라고 한다면, 2주 동안 `Access Token`이 만료되는 1시간 주기마다 `Access Token`을 새롭게 발급받을 수 있다.

![Attachments_JWT_P01](https://github.com/destitutor/jwt-login/assets/75304316/0564756f-5711-4855-931b-e4c951d2a6b8)

1. 사용자가 로그인을 한다.
2. 서버에서는 회원 데이터베이스에서 값을 비교한다.
3. 사용자의 인증이 완료되면 서버는 `Access Token`, `Refresh Token`을 발급한다.
4. 그 후, 이를 HTTP 응답 헤더에 실어서 사용자에게 보낸다. 이때 일반적으로 회원 데이터베이스에 `Refresh Token`을 저장해둔다.
5. 사용자는 `Refresh Token`을 안전한 저장소에 저장한 뒤에, `Access Token`을 HTTP 요청 헤더에 실어 요청을 보낸다.
6. 서버는 사용자가 보낸 `Access Token`을 검증한다.
7. 그 후 서버는 요청 데이터를 사용자에게 보낸다.

이번에는 시간이 지나서 `Access Token`이 만료되었다고 생각해보자.

![Attachments_JWT_P02](https://github.com/destitutor/jwt-login/assets/75304316/6f54fafa-ad50-4f8b-998b-8367d83a8f84)

9. 사용자는 이전과 동일하게 `Access Token`을 HTTP 요청 헤더에 실어서 보낸다.
10. 서버는 `Access Token`이 만료되었음을 확인한다.
11. 서버는 사용자에게 권한 없음(403: Unauthorized)으로 신호를 보낸다.
12. 사용자는 `Refresh Token`과 `Access Token`을 HTTP 요청 헤더에 실어 보낸다.
13. 서버는 받은 `Access Token`이 조작되지 않았는지 확인한 후, HTTP 요청 헤더의 `Refresh Token`과 사용자의 DB에 저장되어 있던 `Refresh Token`을 비교한다. `Refresh Token`이 동일하고 유효기간도 지나지 않았다면 새로운 `Access Token`을 발급해준다.
14. 서버는 새로운 `Access Token`을 HTTP 응답 헤더에 실어 다시 API 요청을 진행한다.

## RTR(Refresh Token Rotation)
웹 애플리케이션은 네이티브 애플리케이션보다 쉽게 위협에 노출될 수 있기 때문에, Refresh Token에 대한 추가적인 보호가 필요하다. 구체적으로 말하면, 브라우저에 노출되는 리프레시 토큰은 `RTR(Refresh Token Rotation)`을 통해 보호되어야 한다.

`Refresh Token Rotation`은 간단히 말해서 `Refresh Token`을 한 번만 사용할 수 있도록 만드는 것이다. 리프레시 토큰이 사용될 때마다, 보안 토큰 서비스는 새로운 `Access Token`과 `Refresh Token`을 발급한다.

![Attachments_JWT_P03](https://github.com/destitutor/jwt-login/assets/75304316/e51b0bcd-8747-4ba7-8605-1e88e8d6461e)

하지만 단순히 리프레시 토큰을 발급하는 것만으로는 추가적인 보호를 제공하진 않는다. 그래서 RTR의 두 번째 측면이 매우 중요한데, 보안 토큰 서비스(STS)는 리프레시 토큰이 두 번 이상 사용되는 것을 감지하면 문제가 있다고 판단하기 때문이다. 그럼 리프레시 토큰은 즉시 폐기되어야 하고, 그와 관련된 모든 토큰도 같이 폐기되어야 한다.

![Attachments_JWT_P04](https://github.com/destitutor/jwt-login/assets/75304316/4c303f7e-c20f-4057-8072-a12233f12339)

공격자가 앱보다 먼저 훔친 토큰을 사용하는 경우를 방지하기 위해서, 모든 관련 토큰을 폐기하는 것이 중요하다.

![Attachments_JWT_P05](https://github.com/destitutor/jwt-login/assets/75304316/484eb100-9dcf-471d-be17-d8767b8fa102)

# 스프링 부트 시큐리티
## 의존성 추가
### Gradle
```groovy
compileOnly 'io.jsonwebtoken:jjwt-api:0.11.5'
runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.5'
runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.11.5'
```

## 시큐리티 설정
- CORS를 활성화하고 CSRF를 비활성화한다.
- 세션 관리를 stateless로 설정한다.
- 인가되지 않은 요청에 대한 예외 핸들러를 설정한다.
- 엔드포인트(endpoint)에 대한 사용 권한(permission)을 설정한다.
- JWT 토큰 필터를 추가한다.

> 일반 사용자가 브라우저를 통해 처리할 수 있는 모든 요청에 대해서 CSRF 보호를 사용하는 것이 좋다. 브라우저가 아닌 클라이언트에서 사용하는 서비스만 만드는 경우 CSRF 보호를 사용하지 않도록 설정할 수 있다.

# 참고
1. [An in-depth look at refresh tokens in the browser](https://pragmaticwebsecurity.com/articles/oauthoidc/refresh-token-protection-implications.html)
