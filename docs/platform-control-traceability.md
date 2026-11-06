# 플랫폼 통제와 두 제안서의 22개 검사 대응

기준: platform `b19488e2debbee8bbe120f1309eadbe19df85b6f`, security catalog
`security-modernization.v1`. 원문 요구 ID는 `domain/security_program.py`의 CHECKS가
정본이며 [원문 요구사항 연결](architecture-integration.md)과 함께 읽는다.

플랫폼 T5의 **6개 범주**는 비밀 저장(SEC-01/ENC-02), 전송 암호화(ENC-01), 감사(AUD-01),
네트워크(NET-01), 최소 권한(IAM-01/ISO-01), 복구(DR-01)다. 범주 수와 하위 시험 수를
혼동하지 않는다. 아래 연결은 증거를 가져올 위치이며 PASS를 자동 전환하는 규칙이 아니다.

| 추가 검사 | 시점·대상 | 관련 T5 원본/플랫폼 책임 | 별도로 필요한 근거 |
|---|---|---|---|
| risk-assessment | 사전·출발지 | IAM-01.2의 제한된 구성 점검, T16/T33 | 현재 자산·노출·취약점·수집 성공/실패, 위험 우선순위 |
| proposal-scope | 사전·목적지 | T11/T15/T38 | 정확한 diff·이미지·계획, 보호 경로/권한, 모델의 실행 권한 부재 |
| sandbox-isolation | 사전·목적지 | NET-01/ISO-01은 관련 운영 범위만 | 리허설 자격 부재, egress·metadata·다른 작업 접근 거부와 정상 대조군 |
| rehearsal | 사전·목적지 | T15/T38 | 동일 계획의 격리 리허설, 회귀·성능·변경 영향, 실행 산출물 digest |
| source-compatibility | 사전·출발지 | T14 원본, T20/T35 | 앱·DB·프로토콜·데이터 계약과 현재 출발지 revision |
| target-compatibility | 사전·목적지 | T14 원본, T20/T35 | 목적지에서 같은 의미의 기능/데이터 시험, 공급자 차이 |
| identity-boundary | 사전·목적지 | SEC-01.1/.4, IAM-01.1/.2, ISO-01.1, T7/T9 | workload audience/UID·철회, 서비스 역할의 직접 변경 거부, 사람 권한/직무 분리 |
| web-session | 사전·목적지 | 직접 대응 없음 | 외부 웹/IdP의 MFA, 세션·CSRF·CSP·XSS, 웹과 API 각각의 실제 인가 |
| resource-budget | 사전·목적지 | 직접 대응 없음 | 요청·큐·동시성·시간·비용 한도와 초과 시 앱 가용성 |
| network-tls | 사전·목적지 | ENC-01.1~.5, NET-01.1~.3 | 모든 등록 경로, 원본/대조군, DB·pooler 양쪽 bundle; 서비스 TLS는 별도 경로 |
| artifact-provenance | 사전·목적지 | SEC-01.2는 비밀 검사의 일부 | 빌드 출처·의존 잠금·검증된 commit/wheel/image digest, 승인된 발행자 |
| approval-binding | 사전·목적지 | T10 현재 승인 | 실제 계획 잠금 안의 승인/계획/diff/digest/등록 재확인 |
| effect-reconciliation | 사전·목적지 | T10/T31/T12 | 단일 접수, 응답 유실 후 원장 조회, 불명확 결과에서 재적용 금지 |
| recovery-assets | 사전·목적지 | DR-01.1은 복원 결과의 일부, T12/T13 | 백업·키·이미지의 독립 접근/삭제 거부, 복구 계획과 예상 RPO/RTO |
| protection-parity | 사전·목적지·이전 전용 | T14 원문과 T19 6개 범주 대조 | 추가 요구 전체와 출발지/목적지 method·revision 결속; T19 PASS만으로 충분하지 않음 |
| data-cutover | 사전·목적지·이전 전용 | T12/T13/T20/T35 | 쓰기/복제 경계, 데이터 손실·정합성·복구 조건, 전환 계획 |
| runtime-verification | 사후·목적지 | T10/T31 반영 기록 | 실제 application/operation ID 이후 기능·성능·인가 거부·민감정보 노출 재시험 |
| patch-reassessment | 사후·목적지 | T16/T33 | 실제 변경된 자산·이미지·새 스캔과 해결/잔존 위험, 실패 coverage 보존 |
| recovery-verification | 사후·목적지 | DR-01.1, T12/T13/T20/T35 | 실제 복원·업무 기능·데이터 내용·측정 RPO/RTO; 연결 성공/행 수만으로 전체 무결성 주장 금지 |
| continuous-revalidation | 사후·목적지 | T33와 기존 감시 작업 | 만료·드리프트·철회 탐지, 보류 전달, collector 장애/원본 최신성 |
| audit-trail | 사후·목적지 | AUD-01.1~.3, T24 | 실제 변경/거부/승인/근거의 연결, 수집·보존·변조 방지; 로컬 JSONL은 보조 진단 |
| runtime-parity | 사후·목적지·이전 전용 | T14/T19 post_apply | 실제 반영 이후 새 revision의 전 범주/추가 요구 재진단 |

## 결속과 미확인 처리

1. 기존 `TeamControlRegistration`에 app/environment/role, schema digest, test ID,
   method version, expected/control 조건을 명시한다. 원문 전체는 기존 신뢰 경로로 검증한다.
2. `ProgramEvidenceRoute`는 해당 검사에 필요한 **모든** 원본과 issuer를 연결한다.
   하나의 제한된 TLS PASS를 identity/웹/복구 통과로 투영하지 않는다.
3. source/target method가 다르거나 DB/pooler 원문 중 하나가 없거나 허용 대조군이
   실패하면 PASS를 만들지 않는다. 새 method는 별도 등록하고 v1을 v2로 이름만 바꾸지 않는다.
4. T10의 `initial/post_apply`와 프로그램 `preflight/postflight`는 서로 다른 축이다.
   `post_apply`에도 그 단계의 사전 검사가 있을 수 있다. 프로그램 postflight는 실제
   operation ID와 not_before 이후 관측을 요구한다.
5. T19의 기존 판정/예외와 추가 프로그램 조건을 함께 유지한다. 추가 검사에 증거가 없으면
   UNKNOWN이며, 과거 환경 PASS·문서·도구 설치·로컬 합성 결과로 채우지 않는다.

현재 추가 서비스의 실측은 로컬 TLS·PostgreSQL·실제 플랫폼 모듈/SQLite 소비 시험이다.
팀 클러스터의 위 22개 전체 인수 상태는 **미검증**이다. 각 공급자 원본을 확보한 이후에만
개별 상태를 바꾼다. 관련 플랫폼 원문은
[고정 T5 문서](https://github.com/Softbank-Hackathon-Finals/platform/blob/b19488e2debbee8bbe120f1309eadbe19df85b6f/docs/controls/README.md)를 따른다.
