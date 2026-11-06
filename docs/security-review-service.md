# 제한된 보안 판정 서비스

현재 기준 플랫폼: `b19488e2debbee8bbe120f1309eadbe19df85b6f`.
최초 기준 `f602b39a949b99f3e2e7be901103063e78a52a70`도 별도 소비 시험으로 유지한다.
`T10ProgramAuthority`의 `baseline_sha`는 호스트의 검증한 실제 소스에 맞춰 명시한다.
기본값은 현재 기준이며 실행 시 Git을 조회하거나 버전을 자동 추측하지 않는다. 구현은 개인 환경용이다.
실제 클러스터의 T7 audience·CNPG 역할·NetworkPolicy·T24 인수는 아직 수행하지 않았다.
선택 이유는 [ADR-0001](adr/0001-security-review-service.md), DB 격리는
[ADR-0002](adr/0002-tenant-fixed-service-reader.md)에 기록한다.

## 책임과 신뢰 경계

공통 패키지는 정책과 증거 계약의 정본이다. 서비스는 현재 등록된 프로그램의 검사만
수행한다. `POST /v1/program-reviews` 외의 등록·실행·승인 API는 없다. 서비스에
배포/비밀 읽기/자격 발급 권한을 주지 않는다. 플랫폼은 기존 T10 승인/잠금, T19 판정,
T31/T12 실행, T24 감사 및 원장을 소유한다. 원격 PASS는 추가 조건이며 실행 허가가 아니다.

```text
기존 T7 발급 → 호스트의 짧은 수명 토큰 → 고정 TLS 서비스
                                          ↓ 매번 TokenReview + 현재 UID/범위 등록
현재 호스트 계획 → 등록 context → SELECT 전용 테넌트 DB → 현재 원본 서명/철회/hold
                                          ↓ 요청 nonce에 결속한 최대 5초 결과
기존 T10/Sova 승인·계획 잠금·effect CAS → 한 번 접수 → 기존 실행기 → 사후 새 관측
```

서비스 침해 시 거짓 판정 위험은 남는다. 독립 측정자 키, 등록자, 서비스 읽기 계정,
실행 계정을 분리하고 실행기 자체 IAM/RBAC로 우회 경로를 닫아야 한다. 네트워크 서비스
분리만으로 그 속성이 입증되지는 않는다. 일반 앱 트래픽은 이 API를 거치지 않는다.

## 등록과 요청

`ReviewRegistration`은 기존 `SecurityProgram`, 현재 호스트 context, 검사 단계,
등록 유효기간을 결속한다. 기존 `PostgresSecurityArtifacts.register`를 별도 인가된
관리 경로에서 사용한다. 런타임은 등록 데이터를 만들거나 수정하지 않는다.

`HostReviewBinding`에는 호스트 종류·고정 소스 SHA·plan ID/digest·원래 context digest·
profile ID/version·gate phase·application ID가 있다. 플랫폼 profile version은 문자열이다.
`initial/post_apply`와 `preflight/postflight`는 독립 축이다. 사후 검사에는 실제 operation ID와
관측 하한 `not_before`를 등록하며, 실제 반영과 사후 증거의 결속은 기존 실행기의 책임이다.

전송은 `modernization_codec.encode/decode`를 사용한다. 추가 wire kind는
`security-review-registration.v1`, `security-review-request.v1`, `security-review-response.v1`이다.
요청에는 정확한 scope, 등록 fingerprint, 256비트 요청 nonce, `enforce/shadow` 모드만 있다.
호출자가 actor·정책·증거·승인·결과를 제출할 수 없다. 미등록/타 tenant는 근거 조회 전에 거부한다.

응답의 모든 binding, 검사 목록/참조, PASS 근거 ID, 유효기간을 검증한다. nonce가 다른 응답,
이전 등록, shadow를 enforce로 바꾼 응답, 만료 결과, None 인증 결과는 허용하지 않는다.
`execution_authorized`는 항상 false다. 응답은 서명된 원본 증거나 T19 판정을 대체하지 않는다.

## 신원과 시간

`ExecCredentialProvider`는 기존 T7 표준 ExecCredential 반환을 소비하며 토큰을 새로 발급하지
않는다. `TokenReviewAuthenticator`는 고정 API TLS origin·audience와 현재 ServiceAccount UID를
대조한다. 토큰의 그룹/tenant 주장은 권한 등록에 사용하지 않는다. JWT를 로컬 파싱하는 부분은
시간 범위 확인이며 서명 인증이 아니다. 성공한 온라인 TokenReview가 매번 필요하다.

서버는 원본 검증 전후와 감사 기록 후 신원·등록을 다시 조회한다. 인증 성공 캐시나 이전 PASS
대체 경로는 없다. projected token과 grant 파일은 호출마다 읽으므로 원자적 파일 교체를 반영한다.
CA/서버 TLS 인증서는 프로세스 시작 시 읽으므로 교체 후 재시작한다. 키는 코드/JSON 응답/로그에 넣지 않는다.

TTL은 최대 5초이며 검증 시간, 토큰·등록·근거 만료 중 가장 이른 값으로 줄인다. 양쪽 시계가
동기화되어 있어야 한다. 현재 구현은 허용 clock skew를 추측하지 않고 미래/역행을 거부한다.
원격 철회와 플랫폼 트랜잭션 사이에 분산 원자성을 제공하지 않는다. 즉각 철회가 필요한 운영
집행에서는 같은 계획 잠금을 사용하는 로컬 철회/fencing 기록을 함께 갱신해야 한다.

## 실행

검증한 wheel의 `service` extra를 설치한다. 비밀은 T9/OpenBao 등의 보호된 mount로 제공한다.
다음 설정은 형식 예시이며 실제 등록 자료나 자격을 제공하지 않는다. 모든 경로는 절대 경로다.

```json
{
  "schema_version": 1,
  "tenant_id": "registered-tenant",
  "database_dsn_file": "/run/database/dsn",
  "tokenreview_origin": "https://registered-api.example.invalid:6443",
  "tokenreview_ca_file": "/run/api/ca.crt",
  "reviewer_token_file": "/run/api/token",
  "audience": "registered-security-review-audience",
  "grants_file": "/run/grants/grants.json",
  "local_audit_file": "/var/log/security-review/reviews.jsonl"
}
```

```sh
python -m sova_security.interfaces.review_server \
  --config /run/config/config.json --certificate /run/tls/tls.crt \
  --private-key /run/tls/tls.key --host 127.0.0.1 --port 8443
```

기본 바인딩은 loopback이다. TLS를 종료한 뒤 평문으로 전달하는 reverse proxy 설정은 지원하지
않는다. TLS passthrough 또는 직접 TLS를 사용하고 전달 헤더를 신뢰하지 않는다. 호출자는
등록된 고정 origin만 쓰며 redirect/proxy/재시도를 사용하지 않는다. HTTP body 16KiB,
응답 256KiB 기본 한도, 16개 작업 슬롯, 전체 body+작업 5초 응답 기한을 둔다. 기한이 지난
blocking worker는 끝날 때까지 슬롯을 점유한다. 무한 대기 작업을 무한히 추가하지 않는다.
Python DNS/일부 SDK 호출의 강제 취소까지 보장하지 않으므로 배포의 프로세스 감시·네트워크
기한·작업 한도를 함께 적용한다. DB 연결/문장 기한도 별도로 제한한다.

DB는 verify-full TLS 또는 등록한 사설 Unix socket만 허용한다. 전용 reader 역할과
테넌트별 restrictive RLS를 먼저 준비해야 하며 공유 쓰기 계정으로 시작할 수 없다.
`review_database.reader_statements(role=..., tenant_id=...)`가 비밀 없는 DDL을 반환한다.
새 역할을 별도 관리자 트랜잭션에서 만들고, 로그인 자격은 기존 비밀 관리 경로에서 설정한다.

grant mount는 정확히 `schema_version: 1`, `grants: [...]`를 가진다. 각 항목에는
`username`, `uid`, `subject_id`, `tenant_id`, `scopes`, `modes`, `issued_at`, `valid_until`이 필요하다.
scopes는 전체 ResourceScope 객체 배열이며 같은 tenant 내 source/target을 명시한다.
최대 64개 grant, 중복 신원 금지다. 등록 파일을 API 호출자가 수정할 수 있으면 경계가 무너진다.

## 감사와 장애

DB 연결은 요청별로 한 번 열고 각 저장소 호출은 READ COMMITTED의 현재 자료를 읽는다.
처음과 요청 종료 시 고정 tenant/SELECT 정책을 확인한다. 원본 증거 묶음도 전후 현재
등록·서명·철회를 재검증하며 행이나 PASS를 캐시하지 않는다. 상세 결정과 성능 시험은
[ADR-0003](adr/0003-request-scoped-live-evidence.md)에 있다.

로컬 JSONL은 fsync한 진단 기록이며 T24 불변 감사가 아니다. 단일 프로세스/파일, 보호된
영속 볼륨, 별도 전송·보존·용량 경보가 필요하다. `computed`는 응답 전달/실행 완료를 뜻하지
않는다. 기록 실패 시 성공 응답을 보내지 않는다. 거부 기록마저 실패하면 거부는 유지하고,
외부 모니터가 로그 저장 실패를 감지해야 한다. 실행 영수증은 원래 플랫폼 원장에 남긴다.
로컬 파일은 기본 16MiB에서 추가 기록을 중단하고 신규 판정을 보류한다. 조용히 옛 기록을
덮거나 삭제하지 않는다. 운영에서는 기존 T24 전송·보존 확인 후 회전하며, 인가된 담당자가
로그 경로를 관리한다. 이 용량 제한은 전체 PVC/노드 사용량 한도를 대신하지 않는다.

서비스/TokenReview/DB/감사 장애, 증거 UNKNOWN, 철회 또는 만료 시 신규 변경을 보류한다.
이미 APPLIED인 효과는 재전송하지 않는다. 앱을 이 서비스의 readiness에 종속시키지 않는다.
자동 rollback/강제 승인/장기 토큰 대체 경로는 없다. 복구는 별도 승인된 기존 계획을 따른다.

### 침해 대응의 철회 지연

실제 로컬 Kubernetes 1.35.0 시험에서 bound Secret/SA 삭제가 TokenReview 거부로 보이기까지
각각 약 10초가 걸렸다. 온라인 TokenReview도 삭제 즉시의 전역 철회를 보장하지 않는다.
이 값은 로컬 관측이며 운영 환경의 최대 지연을 보증하지 않는다.

침해 대응은 기존 호스트의 승인/권한/보류를 plan lock 아래 현재 상태로 차단하고, 별도
보안 hold를 등록한 뒤 T7의 bound object/자격 철회를 수행하는 순서로 인수한다.
서비스의 `PostgresReviewHost`는 기존 hold 저장소를 매 판정에서 확인한다. 실제 시험에서
삭제 직후 TokenReview가 아직 성공하더라도 현재 hold는 다음 T10 접수를 약 0.085~0.087초에
거부했고 외부 실행은 0회였다. 이 시험은 이후 새 요청의 거부이며 이미 dispatch된 작업을
소급 취소하거나 서로 다른 DB의 원자성을 입증한 것이 아니다.

운영 host-side 보류/등록 writer도 동일 계획 잠금을 사용해야 한다. 이미 접수한 작업은
원장과 실제 실행 상태를 조정한다. 새 자격 발급만으로 보안 hold를 해제하지 않으며 기존
독립 복구·해제 승인을 유지한다. [실제 API 시험 결정](adr/0004-local-kubernetes-authentication.md).

### 서비스 자체가 침해된 경우

테넌트 고정 SELECT 역할과 최소 Kubernetes RBAC는 직접 변경·타 테넌트 조회 범위를 줄인다.
그것만으로 침해된 서비스가 거짓 판정을 응답하지 못한다고 보장하지는 않는다. TLS는 상대
신원/전송을 보호하며 실행 중인 프로세스의 무결성을 증명하지 않는다. 그래서 플랫폼의 기존
T19 원본 검사·현재 승인·실행 권한을 계속 독립적으로 집행한다. 추가 서비스 PASS가 그 조건을
덮어쓸 수 없다. trust/등록 writer·TLS 키·배포 이미지와 호스트는 별도 운영 신뢰 경계다.

로컬 감사 파일은 서비스가 소유하므로 침해 후 변조 방지 저장소가 아니다. 과거 감사의
보존은 서비스가 삭제할 수 없는 T24 수집/보관 권한으로 인수해야 한다. 서비스 배포나 DB
관리자까지 침해한 상황을 현재 읽기 전용 계정 시험의 방어 범위로 확대하지 않는다.

## Kubernetes 명세와 인수

`python -m sova_security.interfaces.review_manifest --registration /absolute/deployment.json`
명령은 Kubernetes List JSON만 출력하며 apply하지 않는다. 등록 형식은
`tests/unit/test_review_manifest.py`에 있다. image는 registry의 정확한 digest여야 한다.
테넌트별 namespace, 호출자 namespace+app, API/DB 단일 IP+port, 서로 다른 API/service
audience를 요구한다. 이미지 내용·서명은 별도 공급망 검증 대상이다.

생성 결과는 non-root, readonly rootfs, 모든 capability 제거, seccomp, 자동 SA 토큰 mount 해제,
명시한 API audience의 짧은 projected token, tokenreviews/create만 가진 역할, 제한된 ingress/
egress를 포함한다. namespace, TLS/DB Secret, grants/CA ConfigMap, 감사 PVC는 별도 운영
등록이 필요하다. 비밀/자격은 생성하지 않는다. 하나의 로컬 감사 파일을 여러 프로세스가 공유하지
않도록 replicas=1/Recreate다. 재시작 중 변경 판정은 보류되며 기존 앱은 계속 제공해야 한다.

TCP probe는 프로세스 수신 여부만 검사한다. 실제 권한·증거가 정상이라는 표시가 아니다.
NetworkPolicy는 다른 정책과 허용 범위가 합쳐지므로 전용 namespace의 정책 전체를 확인해야
한다. CNI의 DNS selector/API 주소 DNAT 처리, IPv6 경로, DB 주소 변경은 실제 거부 시험으로
인수한다. 현재 로컬 명세 시험을 Kubernetes 네트워크 차단 실측으로 표시하지 않는다.

## 소비와 재현

Sova는 `RemoteProgramService`를 기존 `with_patch_security_program`에 조합한다.
현재 구현은 실행 actor와 서비스 workload subject의 명시적 일치를 요구한다. 인간 사용자로
암묵 위임하지 않는다. 위임이 필요하면 호스트가 검증한 별도 계약을 추가해야 한다.

플랫폼은 실제 `T10GateAuthority`에 `T10ProgramAuthority`를 조합한다. `load_session`과
`load_registration(connection, principal, plan, phase)`은 같은 계획 트랜잭션에서 현재 자료를
읽어야 한다. 등록/철회 writer도 같은 계획 잠금을 사용한다. 원격 호출 전후 기존 authority와
등록을 다시 확인한다. nonce/응답 시간은 승인 revision에 넣지 않고 안정적인 등록/session 지문만
결속하므로 매 호출마다 승인이 불필요하게 바뀌지 않는다. upstream T19/SHIFT 검사를 생략할 수 없다.

현재 기준의 `StoredGateServices`는 기존 T10 `GateRecordView`와 같은 계획 트랜잭션에서
현재 서명/권한/예외/T13 공급자를 결합한다. 호스트가 이 경로를 사용할 때 그대로 upstream을
구성하며 우리 쪽에 별도 T19 원장이나 issuer를 만들지 않는다. 새 `CollectedNetworkProofAuthority`의
DB·pooler 양쪽 원문 검증도 유지한다. 단일 네트워크 경로의 성공을 전체 NET 통과로 바꾸지 않는다.

`compare_shadow`는 기존 로컬 판정과 원격 shadow 결과를 비교만 한다. 통신 장애는 unavailable,
검사별 차이는 mismatch로 남긴다. shadow 결과로 운영 승인/기존 상태를 바꾸지 않는다.

```sh
python -m pytest tests/unit/test_review_service.py tests/unit/test_review_identity.py \
  tests/unit/test_review_asgi.py tests/unit/test_review_mounts.py tests/unit/test_review_manifest.py -q
python -m pytest tests/integration/test_review_tls.py -q
# 기존의 명시적 격리 PG fixture 설정 후: 이름/cluster_name 검사 통과 필수
python -m pytest tests/integration/test_postgres_boundary.py tests/integration/test_review_host_runtime.py -q
# 깨끗한 위 SHA의 platform checkout. Python 3.12+ 및 platform-test extra 사용
SOVA_PLATFORM_SOURCE=/absolute/pinned-platform python -m pytest tests/contracts/test_platform_review_bridge.py -q
```

정확한 실행 결과와 미검증 항목은 [개발 기록](development/security-service-2026-11-06.md)에 남긴다.
