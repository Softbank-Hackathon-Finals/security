# 두 보안 제안서의 구현과 검증 연결

2026-11-06 · 0.10.0 통합 기반 + 제한된 서비스 확장 · catalog `security-modernization.v1`

사용자가 제공한 두 설계 제안서를 기존 보안 구현에 연결한다. 원문은
`proposals/patching-as-a-service.txt`, `proposals/incident-security-architecture.txt`에
보존하며 `proposals/manifest.json`에 원문 SHA-256을 기록한다. 사건명·통계·서비스
설명은 제공된 문서의 참고 맥락이다. 이번 구현에서 그 사실관계를 새로 검증하거나
사건 자체를 재현했다고 주장하지 않는다. 통제 판정에는 인증된 시험 근거만 사용한다.

## 저장소 관계와 선택

`security`가 `sova-security`의 구현 정본이다. `sova-test`는 설치한 패키지를 사용하고
기존 `sova.security.*` import 중 추출된 모듈은 호환 alias다. Sova는 작업 원장,
승인, effect CAS, 실제 어댑터, 감시 작업을 소유한다. `platform` 소비자는 Sova 전체를
설치하지 않고 검증한 wheel을 설치하고 현재 팀 계약에 맞는 어댑터를 연결한다.

공통 Python 패키지를 유지하고 선택형 제한 보안 서비스를 추가한다. 0.10.0에서 패키지를
직접 소비하던 선택은 [ADR-0001](adr/0001-security-review-service.md)으로 확장했다.
Sova와 팀 플랫폼은 같은 검증 규칙을 재사용하며 독립 서비스의 권한·장애 경계도 시험한다.
기존 프로그램/원본 wire kind 네 개와 SQL 7개는 유지한다. 서비스 등록/요청/응답 kind 세 개,
테넌트 전용 reader 정책을 추가하며 새 승인 엔진이나 클라우드 실행 자격을 만들지 않는다.
현재 실행·배포·호환 계약은 [보안 판정 서비스](security-review-service.md)를 따른다.

## 원문 요구사항과 실제 연결

| 원문 요구 | 기존 구현·계약 | 이번 통합 검사 | 후속 환경 검증 |
|---|---|---|---|
| SEC-PATCH-01~02 지속 조사·위험 우선순위 | `AssessmentService`, Trivy/CycloneDX/Prowler, CISA KEV 입력 인증 | `risk-assessment` | 등록한 scanner·inventory·노출 근거 공급자 연결 |
| SEC-PATCH-03 AI 수정안 | `RemediationProposal`, 보호 경로·scope·diff 검사 | `proposal-scope` | 실제 모델 생성 diff를 T11/T15에 연결 |
| SEC-PATCH-04 격리·회귀·변경 영향 | `RehearsalAdmissionService`, 원본/목적지 `compatibility`, `data-safety`, `protection` 시험 | `sandbox-isolation`, `rehearsal`, source/target compatibility | Harbor/T15 독립 verifier·격리 자원 실측 |
| SEC-PATCH-05 승인 | `compile_patch`, `PatchExecutionGuard`, host stored approval | `approval-binding` | T10 현재 승인·diff/image/plan 결속 |
| SEC-PATCH-06 적용·복구 | Sova stored executor, Kubernetes image adapter, `require_postflight` | runtime/recovery verification | 실제 적용·복구, 데이터와 업무 기능 검증 |
| SEC-PATCH-07 재스캔 | `reassess_patch`, `PatchRuntimeAuthority` | `patch-reassessment` | 실행 command와 새 inventory/scan 연결 |
| SEC-PATCH-08 이전 전후 보호 | `ProtectionParityGuard`, T5 ControlRun import | `protection-parity`, `runtime-parity` | T14/T19 원본 대조, 목적지 재시험 |
| SEC-PATCH-09 재진단·드리프트 | `ContinuousSecurityMonitor`, Sova 감시 lease/outbox | `continuous-revalidation` | 상시 collector·감시·보류 전달 실측 |
| SEC-PATCH-10 개선 이력 | security artifacts, signed evidence, host effect journal | `audit-trail` | T24 불변 감사 보관·누락 탐지 |
| CTRL-01~02·04 계정·노드 침해 제한 | scope/revision, trust revocation, incident hold | `identity-boundary` | 계정·앱 접근 거부, 폐기 신원, 실제 네트워크 격리 |
| CTRL-03 공급망 | source/image/provenance digest, sandbox bounds | `sandbox-isolation`, `artifact-provenance` | 자격 부재·egress/metadata 거부, 빌드 출처 확인 |
| CTRL-05 웹 세션 | Sova demo 인증 경계와 React 출력 | `web-session` | 기업 IdP·세션·CSP·CSRF·브라우저 XSS 시험 |
| CTRL-06 운영 연속성 | effect reconciliation, 보류, 별도 복구 계획 | `recovery-assets`, `recovery-verification` | 제어면 중단 시 앱 유지·백업 삭제 거부·복원 |
| CTRL-07 비용·가용성 | bounded input/process, host concurrency | `resource-budget` | Edge rate limit·큐·모델/리허설 비용 한도 |
| CTRL-08~09 AI 권한 분리 | 보호 파일·고정 계약·독립 검증·별도 실행 | `proposal-scope` | 모델 출력·도구 호출에서 실제 비인가 실행 0건 |

실행 정책 POL-01~12의 매핑은 `CHECKS`의 `references`에 고정되어 있다.
각 22개 검사와 T5의 6개 범주·하위 시험·추가 근거는
[플랫폼 통제 대응표](platform-control-traceability.md)에 따로 정리했다.
`sova security-program-catalog`로 전체를 조회한다. 기존 SG/CC/T5 및 Sova Gate 번호를
새 번호로 바꾸지 않는다. 원문의 G0~G7은 설명용 번호이며 Sova의 Gate enum과 다르다.

## 새 API의 역할

`SecurityProgram`은 원본·목적지 scope, 기존 계획의 SHA-256, 환경별 revision,
각 검사의 기존 verifier contract, 등록 기간을 결속한다. patch는 19개,
migration은 22개 검사로 구성된다. preflight와 postflight를 나누어 사전 검사를
사후 정상 운영의 근거로 재사용하지 않는다. 패치 프로필에도 원본/목적지 호환성
검사를 요구한다. 같은 환경 패치는 두 scope가 같을 수 있다.

`ProgramBinding`은 기존 `VerificationObligation`을 사용한다. 새 `review_program`
함수는 기존 `evaluate_gate`에 위임하며 필수 검사에서 N/A를 허용하지 않는다.
원본의 성공을 다른 목적지의 성공으로 치환하거나 도구 설치를 PASS로 바꾸지 않는다.
필수 검사 누락·중복·scope 변경·다른 계획의 근거·동일 시각의 모순 근거·만료·미확인은
통과하지 않는다. `obligation_id`에는 정확한 subject digest가 포함된다.

`SecurityProgramService.review`는 호스트가 제공하는 현재 등록, 현재 근거,
등록/근거 인증, 호출자 인가, 보류 확인을 매번 재검사한다. callback 반환은 기존
권한 계약대로 `True` 또는 실패 시 예외를 내는 `None`을 지원한다. 입력의 self-declared
`approved_by`, verifier 이름, 체크섬만으로 인증해서는 안 된다. 서명·등록·폐기 조회는
기존 EvidenceEnvelope/VerifierTrust와 신뢰된 호스트 저장소를 연결한다.

현재 판정 결과는 추가 보안 조건이다. `passed`를 운영 승인이나 T19 PASS로 변환하지
않는다. source/target의 실제 변경 후에는 현재 revision으로 등록과 증거를 갱신한다.
postflight에는 실제 command/배포/관측 결속을 검증하는 기존 `require_postflight`와
reassessment를 계속 사용한다. 이 프로그램 보고서만으로 완료 처리하지 않는다.

## 저장·전송

`modernization_codec.encode/decode`에서 다음 새 타입을 제공한다.

- `security-program.v1`: 호스트가 등록하는 불변 검사 계획.
- `security-program-input.v1`: 등록과 EvidenceRecord 배열. 오프라인 진단 교환용이며 인증이 아니다.
- `program-evidence-route.v1`: 프로그램 검사와 필요한 원본 증거·발급자의 등록.
- `program-evidence-projection.v1`: 원본 envelope까지 추적하는 투영 근거.

등록·근거는 호스트의 기존 저장소에 보관한다. PostgreSQL adapter에 프로그램의 대상
scope와 route/projection의 등록 부모 관계, 활성 등록의 중복·철회 검사를 추가했다.
기존 SQL 7개는 유지한다. 실행은 `RegisteredProgramAuthority`로 현재 등록과
원본 서명을 재검증한다. 설치나 import가 등록 데이터를 생성하지 않는다.

원본 연결·최신 증거 조회·실행 후 관측 시각과 호스트 조합 예시는
[생산자 연결 문서](program-evidence-integration.md)에 있다.

## 검증 수준

`tests/unit/test_security_program.py`는 원문 ID 전체 추적, strict JSON, 누락/만료/
잘못된 scope/revision, N/A, 서명 변조·키 철회·인가 변경을 확인한다. Ed25519 연산은
실제 라이브러리로 수행하며 클라우드 측정값은 합성이다. 별도 PostgreSQL 시험은
실제 RLS·등록·철회·서명 저장·신뢰 키 폐기·최신 실패 증거 전환을 확인한다.

Sova의 `test_security_patch_execution.py`는 실제 SQLite effect 원장과 기존 패치
검증기에 통합하여 검사 누락 시 외부 변경 0건, 승인 철회 차단, 정상 효과 1회,
응답 유실 후 보류 및 미재실행을 확인한다. 실제 이미지 배포·Harbor·WAF·SPIRE·AWS
권한 검증은 이 합성 테스트의 보증 범위에 포함되지 않는다.

정확한 로컬 실행 결과와 남은 인수 항목은 `validation-2026-11-06.md`에 기록한다.
