# 기존 생산자 증거와 프로그램 실행 연결

`sova-security==0.10.0`의 확장이다. 문서의 검사 ID를 나열하는 것에 더해,
기존 생산자 증거 → 현재 등록 → 원본 서명 → 기존 패치 실행 → 사후 검증을 연결한다.
운영 인증·실측 수집기는 호스트가 제공한다.

## 등록과 원본 증거

`ProgramEvidenceRoute`는 정확한 `SecurityProgram.fingerprint`, 검사 ID,
하나 이상의 `ProgramSource`를 결속한다. 각 source는 발급자와 **전체 원본
EvidenceRecord**를 고정한다. 검사당 최대 16개 원본을 요구할 수 있다.

등록은 사용자 JSON을 그대로 저장하는 API가 아니다. 신뢰된 등록 서비스가 원문 통제의
검증 범위를 확인하고 필요한 생산자·시험·대상·revision을 결정한 뒤 인가하여 저장한다.
예를 들어 identity-boundary를 IAM 시험 한 개로 자동 충족시키면 안 된다. 필요한
계정·앱·노드 격리 시험을 등록 정책에서 모두 지정해야 한다. 라이브러리는 실제 시험의
의미나 완전성을 임의 추론하지 않는다.

`SignedProgramEvidence`는 원본 Ed25519 서명을 현재 신뢰 등록과 대조한다.
원본이 하나라도 없으면 해당 프로그램 증거를 생성하지 않아 판정은 UNKNOWN이다.
FAIL은 FAIL, UNKNOWN/N/A는 UNKNOWN으로 유지하고 모든 원본이 PASS일 때만 PASS다.
원본 scope·revision·발급자·전체 record가 등록과 다르면 거부한다.

결과의 `artifact_digest`는 `ProgramEvidenceProjection.fingerprint`이며 그 projection에
프로그램·등록 경로·원본 envelope digest가 들어간다. 새 서명 키로 원본 신뢰를 덮지 않는다.
소비자는 `authenticate_evidence`로 **원본을 매번 재검증**해야 한다. 내보낸 결과 JSON은
독립적인 실행 허가나 서명 증거가 아니다.

## 현재 상태와 PostgreSQL

기존 7개 SQL 마이그레이션을 유지하며 기존 artifact/event와 signed evidence 저장소를 쓴다.

- `PostgresSecurityArtifacts.program(scope, subject_digest)`: 현재 활성 프로그램 하나.
- `program_routes(scope, program_digest)`: 활성 원본 연결 등록.
- 프로그램은 대상 scope에 저장하고, route/projection의 scope는 등록된 부모에서 유도한다.
- 같은 계획의 다른 활성 프로그램, 같은 검사의 다른 활성 route를 덮어쓰지 못한다.
  명시적으로 기존 등록을 철회한 뒤 새 값을 등록한다. 변경 중 빈 구간은 통과하지 않는다.
- `PostgresSignedEvidence.current_envelope`는 scope·원본 obligation·발급자로 등록한
  생산자 채널의 최신 관측을 읽는다. revision이나 verifier version이 바뀌어도 예전 PASS를
  선택하지 않는다. 같은 시각에 여러 원본이 있으면 모호한 상태로 차단한다.
- 원본에 새 FAIL/변경된 근거가 올라오면 과거 PASS를 지정한 route는 더 이상 유효하지 않다.
  단순히 옛 evidence ID를 읽어서 과거 상태를 재사용하지 않는다.

`RegisteredProgramAuthority`가 이 저장소 조회와 원본 검증을 구성한다. DB 행 자체가
발급자 서명이나 호출자 권한을 대신하지 않는다. 등록자는 인가된 쓰기 경로를 사용하고,
실행 소비자는 현재 신뢰·인가·보류 조회를 사용한다.

## Sova 호스트 조합 예시

다음은 이미 구성한 호스트 의존성을 연결하는 코드다. 임의 승인 callback이나
클라우드 자격증명을 만들지 않는다. `scope`와 `plan`은 서버가 읽은 실제 등록 값이다.

```python
from sova_security.adapters.postgres_modernization import PostgresSecurityArtifacts
from sova_security.adapters.postgres_signed_evidence import PostgresSignedEvidence
from sova_security.adapters.postgres_verifier_registry import PostgresVerifierRegistry
from sova_security.adapters.registered_program import RegisteredProgramAuthority
from sova.security.application.security_program import with_patch_security_program

artifacts = PostgresSecurityArtifacts(host.connect_runtime, tenant_id=scope.tenant_id)
signed = PostgresSignedEvidence(host.connect_runtime, tenant_id=scope.tenant_id)
registry = PostgresVerifierRegistry(
    host.connect_runtime, tenant_id=scope.tenant_id, application_id=scope.application_id,
)
authority = RegisteredProgramAuthority(
    artifacts=artifacts, signed_evidence=signed, resolve_trust=registry.resolve,
    scope=scope, subject_digest=plan.fingerprint, clock=host.clock,
)
program_service = authority.service(
    authorize=host.authorize, require_no_holds=host.require_no_holds,
)
secured_patch_service = with_patch_security_program(
    existing_patch_service, program_service, scope=scope,
)
# 이후 기존 execute_step(actor, ..., adapter=...) 인터페이스를 사용한다.
```

이 조합은 기존 서비스 객체를 변경하지 않는다. 기존 승인·effect CAS·패치 guard·runtime
검증·재스캔을 보존하고 프로그램의 preflight와 postflight를 매 호출에 추가한다.
이미 프로그램 정책이 연결된 서비스를 다른 정책으로 조용히 교체하지 않는다.

실행 전에는 준비된 preflight 원본만 등록할 수 있다. 실제 실행 후 verifier가 새 원본을
발행하면 신뢰된 호스트가 postflight route를 등록한다. 사후 근거를 미리 PASS로 만들지 않는다.
비동기 검증이 아직 끝나지 않았으면 보류하고, 기존 effect를 읽어 조정한다.

postflight는 이번 호출 시작 이후 관측을 요구한다. 여러 원본을 합친 record의 시각은
가장 오래된 원본 시각이므로 새 관측 하나로 오래된 관측을 새것처럼 만들 수 없다.
실행 뒤 근거 누락·실패·만료·철회가 생기면 `PatchPostflightRequired`와 기존 hold로
연결한다. 이미 APPLIED인 effect는 유지하며 같은 변경을 재실행하지 않는다.

마이그레이션은 기존 `with_security_program`을 운영 전환 직전의 저장된 계획에 연결하고,
호스트의 실제 전환 후 검증에서 `review(..., phase=POSTFLIGHT, not_before=operation_started)`를
사용한다. 이 라이브러리로 별도 컷오버 엔진이나 데이터 롤백 권한을 만들지 않는다.

## 현재 platform 계약

platform의 `505d451fd8c374de755b160fca24f1a481820a50`에서 통제 schema와 source-run 예제를
대조했다. 새 snapshot은 `schemas/team-control-result-20261106.json`이며 원문 SHA-256은
`f1273e751b31288c6d2ed927d888032474ce05f132dde7545bc12e2d9b38b654`다.

`TeamControlRegistration(schema_digest=CURRENT_SCHEMA_DIGEST, ...)`로 이 snapshot을
명시적으로 선택한다. 기존 등록의 fingerprint를 보존하기 위해 기존 schema/default도 유지한다.
새 schema는 시험 ID와 통제 ID 결속 등을 강화한다. `import_control_run`은 여전히 raw
ControlRun만 받아들이며 GateComparison·예외 승인·평가 context를 실행 권한으로 바꾸지 않는다.
팀 T19 판정기는 그대로 팀의 책임이다. 미래 계약 변경은 해시와 소비 시험을 다시 확인한다.
