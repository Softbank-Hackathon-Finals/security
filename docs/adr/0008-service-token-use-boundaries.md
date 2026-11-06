# ADR-0008: 서비스 토큰의 단일 용도와 원래 수명 제한

- 상태: 구현, 실제 Kubernetes/최신 플랫폼 연결 시험 61 PASS.
- 요구: SG-1, CTRL-01·02·04, POL-01·09·11, SEC-PATCH-10.
- 플랫폼 기준: `9e0d6a59d7a00925ddafc50cfa2ccad00c5ba768`.

## 근거

2025년 Salesloft Drift 사고에서 탈취한 연동 OAuth 토큰이 다른 서비스 자료에 접근하는 데
사용됐다. Google 조사팀은 연결된 다른 자격도 조사·철회하도록 권고했다.
[GTIG 원문, 2025-08-26 및 08-28 갱신](https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift).

2026-09 최종 NIST IR 8587 §5.3.1.3·5.3.1.6은 명시적인 audience와 최소 범위, 짧은 workload
토큰 수명을 다룬다. 여기서는 설계 참고로 사용하며 인증·법규 준수를 주장하지 않는다.
[NIST 원문](https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8587.pdf).

## 결정

Kubernetes TokenReview는 요청한 audience와 토큰 audience의 교집합을 돌려준다. 서비스
audience에 대한 성공만 확인하면 Kubernetes API에서도 사용할 수 있는 복수 audience 토큰을
구별하지 못한다. 기존 정책은 별도 audience를 요구했지만 이 경우를 명시적으로 거부하지 않았다.

서비스 인증기는 토큰 `aud`가 서비스 값 하나의 문자열 또는 원소 하나인 배열인지 검사한다.
누락·중복·다른 audience와의 결합을 거부한다. 응답의 audience도 요청한 한 값이어야 한다.
또한 원래 발급 수명 `exp - iat`가 0초 초과 600초 이하인지 검사한다. 만료 직전에 오래된
토큰을 제출해서 남은 시간만 짧게 보이게 해도 허용하지 않는다. **600초는 기존 projected
token 명세에 맞춘 이 서비스의 선택**이며 NIST가 정한 보편적 상한이라고 설명하지 않는다.

이 파싱은 거부 조건이다. 정상 형식만으로 인증하지 않으며 동일 토큰의 현재 온라인
TokenReview·UID·grant·시간 검사를 계속 수행한다. TokenReview 호출을 위한 reviewer의
Kubernetes API 토큰은 별도 자격이며 이 소비자용 단일 audience 정책과 혼동하지 않는다.
T7 발급기나 API의 전역 정책은 바꾸지 않고, 새로운 issuer·refresh endpoint도 만들지 않는다.

기존 600초 서비스 전용 projected token은 그대로 연결된다. 외부 T7 확장 인계 시에도
서비스용 audience 하나·600초를 요청해야 한다. 스키마와 T10/T19 승인/집행 의미는 유지한다.

## 검증과 한계

단위 시험은 600초 경계, 원래 수명 초과, 오래됐지만 아직 만료하지 않은 토큰, 누락·복수·중복
audience, 정상 형식 이후 온라인 철회를 검사한다. 실제 Kubernetes API에는 600초 복수 audience와
3,600초 단일 audience 토큰을 별도로 요청해 TokenReview의 성공과 보안 서비스의 거부를 비교한다.
잠금 Python 3.14와 실제 PG/API 및 최신 플랫폼을 묶은 시험은 **61 PASS, 85.04초**였다.
Kubernetes가 두 넓은 자격을 인증했지만 서비스는 거부했고 기존 좁은 자격은 계속 성공했다.

토큰은 여전히 bearer 자격이다. 유효한 서비스 토큰을 훔치면 같은 허용 범위에서 재사용할 수
있으므로 짧은 수명만으로 탈취를 해결했다고 주장하지 않는다. 현재 hold·UID 철회·경로 제한·
독립 실행 권한을 함께 사용한다. mTLS/DPoP 같은 송신자 결속은 기존 플랫폼의 신원/인증서
공급과 클러스터 배포 설계가 필요하며 임의의 새 PKI로 대체하지 않는다.
