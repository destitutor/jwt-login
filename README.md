이 리포지토리는 JWT에 대한 개인적인 공부를 위해 사용하고 있습니다. 주로 JWT에 대해 공부한 내용이나 코드를 정리해서 올리고 있습니다.

# Table of Contents
- [정의](#정의)
- [작업 흐름](#작업-흐름)
- [구조](#구조)
  * [헤더(Header)](#헤더header)
  * [페이로드(Payload)](#페이로드payload)
    + [표준 스펙](#표준-스펙)
  * [서명(Signature)](#서명signature)
- [암호화 과정 대략적으로 살펴보기](#암호화-과정-대략적으로-살펴보기)
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

# 구조
JWT는 '헤더-페이로드(payload)-서명(signature)'와 같은 구조를 가지고 있다. 각각의 구성 요소는 점(.)으로 구분되어 있다.

## 헤더(Header)
헤더에는 보통 토큰의 타입이나, 서명 생성에 어떤 알고리즘이 사용되었는지 저장한다. 아래의 경우에는 현재 토큰의 타입이 JWT이고, HS512 알고리즘이 적용된 사실을 확인할 수 있다.

```json
{
	"typ": "JWT",
	"alg": "HS512"
}
```

## 페이로드(Payload)
페이로드(payload)에는 보통 claim이라고 부르는 '사용자에 대한, 혹은 토큰에 대한 프로퍼티(property)'를 키-값의 형태로 저장한다. 즉, claim은 말 그대로 토큰에서 사용할 정보의 조각이라고 할 수 있다.

여기서 중요한 점은 JWT의 페이로드에 있는 정보를 모든 사람이 볼 수 있다는 것이다. 그래서 페이로드에는 비밀번호 같은 민감한 정보가 들어가서는 안 된다.

### 표준 스펙
표준 스펙상 key의 이름은 3글자로 되어 있다. 참고로, 이러한 표준 스펙으로 정의되어 있는 claim 스펙이 있다는 것이지 꼭 이 7가지를 모두 포함해야 하는 건 아니다. 상황에 따라서 해당 서버가 가져야 할 인증 체계에 따라 사용하면 된다.

1. **iss(issuer):** 토큰 발급자
2. **sub(subject):** 토큰 제목 (토큰에서 사용자에 대한 식별값이 됨)
3. **aud(audience):** 토큰 대상자
4. **exp(expiration time):** 토큰 만료 시간
5. **nbf(not before):** 토큰 활성 날짜 (이 날짜 이전의 토큰은 활성화 되지 않음을 보장)
6. **iat(issued at):** 토큰 발급 시간
7. **jti(JWT Id):** JWT 토큰 식별자 (issuer가 여러 명일 때 이를 구분하기 위한 값)

## 서명(Signature)
서명은 페이로드가 위변조되지 않았다는 사실을 증명하는 문자열이다. base64 방식으로 인코딩한 헤더와 페이로드, 개인키(secret key)를 더한 후에 서명한다. 서명은 서버에 있는 개인키로만 복호화 할 수 있으므로 다른 클라이언트는 임의로 서명을 복호화할 수 없다.

```JSON
HMACSHA256 {
  base64UrlEncode(header) + '.' +
  base64UrlEncode(payload),
  your-256-bit-secret
}
```

# 암호화 과정 대략적으로 살펴보기
아래 그림을 보면 헤더와 페이로드가 마침표(.)로 구분되어 있으며, 각각 URL 안전한(URL-safe) base64로 인코딩 되었음을 확인할 수 있다.

> **Note**
> **URL 안전(URL-safe)**
> 
>JWT의 일부분(헤더, 페이로드 등)을 표현할 때 Base64url 코딩 방식을 사용한다. 이는 "URL-safe base64"라고도 한다.
>
>보통 Base64 인코딩은 결과 문자열에 '+', '/', '=' 이 세 가지 문자를 포함한다. 하지만 이 세 문자는 URL과 파일 시스템에서 특수한 의미를 가지기 때문에, 이를 그대로 사용하면 문제가 발생할 수 있다.
>
>따라서 URL 안전한 버전인 Base64url이 제안된 것이다. Base64url은 '+', '/', '=' 문자 대신에 각각 '-', '\_', '' 문자를 사용해서 인코딩을 수행한다.

<p align="center"><img src="https://github.com/destitutor/jwt-login/assets/75304316/da114c37-7e1f-4fc9-8f8b-51120d42d550" width="50%"></p>

시그니처(signature, 혹은 HMAC 태그)는 비밀 키(secret key)와 메시지(base64로 인코딩된 헤더와 페이로드)를 혼합하여 그 결과를 해시 함수를 통해 해싱한 다음 URL 안전한 base64로 인코딩되어 JWT의 마지막 섹션을 차지하게 된다.

<p align="center"><img src="https://github.com/destitutor/jwt-login/assets/75304316/d2d99b6e-c401-40b7-811c-a1d7d04fc45d" width="50%"></p>

이를 친숙한 자바 코드로 나타내면 다음과 같다.

```java
// JSON에서 불필요한 공백을 모두 제거한다.
String header = '{"alg":"HS256"}';
String claims = '{"sub":"Joe"}';

// UTF-8로 인코딩한 바이트 배열을 Base64Url로 인코딩한다.
String encodedHeader = base64URLEncode(header.getBytes("UTF-8"));
String encodedClaims = base64URLEncode(claims.getBytes("UTF-8"));

// 인코딩된 헤더와 클레임을 마침표 문자 '.' 기호로 연결한다.
String concatenated = encodedHeader + '.' + encodedClaims;

// 강력한 암호화 시크릿 키 혹은 개인 키와 함께 원하는 서명 알고리즘(여기서는 HMAC-SHA-256을 사용함)을 사용하여 연결된 문자열에 서명한다.
SecretKey key = getMySecretKey();
byte[] signature = hmacSha256(concatenated, key);

// 서명(signature)는 항상 바이트 배열이므로, 서명을 Base64Url로 인코딩하고 마침표 문자 '.' 기호를 통해 연결된 문자열과 결합한다.
String compact = concatenated + '.' + base64URLEncode(signature);

// eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJKb2UifQ.1KP0SsvENi7Uz1oQc07aXTL7kpQG5jBNIybqr60AlD4
// 이를 'JWS'라고 부르는데, '서명된 JWT(signed JWT)'의 줄임말이다.
System.out.println(compact);
```

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
2. [Java JWT: JSON Web Token for Java and Android - GitHub](https://github.com/jwtk/jjwt)
