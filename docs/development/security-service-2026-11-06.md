# 보안 서비스 개발 기록

## 2026-11-06 시작

- 사용자 범위: security/sova-test의 개인 환경 구현·검증·기능별 커밋·푸시.
- 기존 기반: security `3093814`, sova-test `7d79d65`, 패키지 0.10.0.
- 작업 브랜치: 두 저장소 `feature/security-service-integration`.
- platform 기준: `f602b39a949b99f3e2e7be901103063e78a52a70` (읽기 전용 확인).
- 두 원문: `docs/proposals/manifest.json`의 바이트 지문 유지.
- 설계: [ADR-0001](../adr/0001-security-review-service.md).
- 계획: 등록 context/전송 계약 → 인증·판정 서비스 → HTTPS 소비/병행 판정 →
  Sova 실행 연결 → 실제 TLS/DB/프로세스 실패 시험 → 패키징·인계.
- 미검증: 실제 T7 서비스 audience·운영 권한 등록, 플랫폼 실행 집행 연결, 클라우드 인수.
- 시각/상태: 구현 시작. 기존 테스트 통과 수를 새 서비스 검증으로 사용하지 않는다.

## 기록 원칙

각 변경은 요구사항 ID, 기준 SHA, 선택 이유, 코드, 시험 명령/결과, 증거 위치와
미검증 사항을 기록한다. 설계/구현/모의 검증/실환경 검증을 구분한다. 실패 실험과
포기한 대안도 다음 판단에 필요한 근거를 남긴다. 비밀 원문·개인/운영 식별자는 기록하지 않는다.

## SVC-01: 등록·인증·판정 전송 계약

- 요구: SEC-PATCH-05·10, CTRL-01·02·07, POL-01·03·09·11, SG-1·2.
- 기준 SHA: 위 f602b39 전체 값. 기존 정책/증거/승인 계약을 재사용한다.
- 구현: `domain/review_service.py`, `application/review_service.py`,
  `adapters/{review_identity,review_https,remote_review}.py`, `interfaces/review_asgi.py`,
  `application/shadow_review.py`, codec의 등록/요청/응답 kind 세 개.
- 설계 이유: caller 제공 정책/증거를 받지 않고 현재 등록만 조회한다. 온라인 TokenReview,
  고정 audience/SA UID/tenant/scope, 전후 재인증, nonce/context 결속, 최대 5초 기한을 유지한다.
  shadow와 enforce를 분리하고 결과에 실행 권한을 부여하지 않는다.
- 검증: 관련 단위 시험 73 PASS, 실제 로컬 uvicorn TLS 시험 9 PASS.
  잘못된 CA/hostname, redirect, 응답 한도/형식, 철회, 서비스 중단을 검사했다.
- 실패와 수정: Windows localhost의 IPv6/DNS 경로 때문에 2초 기한을 넘던 TLS fixture는
  올바른 IP SAN을 가진 loopback IPv4로 고쳤다. 운영 TLS 검증/기한을 완화하지 않았다.
  HTTP body 수신과 worker의 기한을 합산하도록 수정했고, 만료 worker는 슬롯을 계속 점유한다.
  의도한 30ms 장애 시험 이후 정상 복구 확인은 별도 1초 기한을 사용해 OS 스케줄링 의존을 제거했다.
- 증거: `tests/unit/test_review_{service,identity,asgi}.py`, `tests/integration/test_review_tls.py`.
  로컬 실행 로그는 `.local-notes/service-work/`에 보관하고 비밀/개인 실행 상태는 커밋하지 않는다.
- 상태: 구현 + 로컬 TLS 실측 + 합성 권한/측정 시험. 실제 K8s TokenReview/T7 audience는 미검증.

## SVC-02: 읽기 전용 저장소와 테넌트 고정

- 요구: CTRL-01·02·04, POL-01, SEC-PATCH-10. 기준 SHA 동일.
- 구현: `adapters/{postgres_review,review_mounts,review_database}.py`, `interfaces/review_server.py`.
- 선택: 기존 SQL 7개/저장소를 그대로 사용한다. API 등록/쓰기 권한은 제공하지 않는다.
  GUC 기반 RLS의 한계를 발견하여 [ADR-0002](../adr/0002-tenant-fixed-service-reader.md)를 추가했다.
  별도 역할의 restrictive 고정 tenant 정책과 SELECT만 허용하고 매 연결 정책/권한 drift를 검사한다.
- 검증: PostgreSQL 17.11 실제 isolated cluster에서 등록/프로그램 철회·hold·타 tenant 거부,
  INSERT/DELETE 거부, 직접 SQL tenant 전환, 정책 삭제/변경·쓰기 grant·membership 차단.
  실제 TLS + Ed25519 서명 토큰 검증기 **모형** + PostgreSQL 연쇄 시험 여섯 종류 통과.
- 전체 회귀 중간 결과: security 752 PASS(40.12초), Sova 직전 1,102 PASS/3 SKIP.
  이후 독립 프로세스/배포 명세 추가는 별도로 검증한다. 이 수치를 최종 산출물 수치로 재사용하지 않는다.
- 실패와 수정: mount를 검사하기 전 FIFO open이 대기할 수 있어 NONBLOCK open 후 fstat로 수정.
  Windows 기본 Python에는 jsonschema/psycopg가 없었다. 인터롭은 준비된 `.venv`/Linux 환경으로
  수행했으며 의존성 누락 실패를 제품 오류나 통과로 집계하지 않았다.
- 상태: 로컬 PostgreSQL·TLS 실측. CNPG/OpenBao 운영 역할, 감사 PVC/T24 전달, 클라우드 IAM은 미검증.

## SVC-03: 호스트 실행·플랫폼 계약 연결

- 요구: SEC-PATCH-05·06·08, POL-06·07·09·11, SG-2·3. 기준 SHA 동일.
- 구현: security `adapters/platform_review.py`; Sova `security/application/remote_program.py`.
- 플랫폼: 원래 `PlanGateSession.fingerprint`와 plan digest를 사용한다. `profile_version="1"`,
  `initial/post_apply`, application_id를 보존한다. 실제 `T10GateAuthority` 전후 검사를 호출하며
  동일 transaction에 전달하는 `load_registration`을 추가해 host plan lock 책임을 명시했다.
  원격 호출을 잠금으로 간주하지 않는다. 승인 revision은 안정적인 context 지문만 결속한다.
- 검증: 고정 platform 소스의 실제 모듈/SQLite 승인·단일 dispatch·응답 유실 조정 15 PASS.
  측정값/신원 공급자는 합성이며 플랫폼 배포 인수와 구별한다.
  Sova 기존 SQLite effect/패치 실행 시험 31 PASS: 사전 실패 효과 0회, 사후 실패 APPLIED+hold,
  재시도해도 재적용 없음, shadow 비교가 실행하지 않음.
- 상태: 구현 + 소비 계약/로컬 원장 실측. 실제 platform 연결은 인계 대상이며 원본 저장소를 수정하지 않았다.

## SVC-04: 진행 중 플랫폼 변경의 별도 인수

- 새 기준: `b19488e2debbee8bbe120f1309eadbe19df85b6f`, 최초 f602b39보다 46개 커밋 진행.
  [비교](https://github.com/Softbank-Hackathon-Finals/platform/compare/f602b39a949b99f3e2e7be901103063e78a52a70...b19488e2debbee8bbe120f1309eadbe19df85b6f).
- T19 StoredGateServices는 같은 T10 GateRecordView transaction에 현재 서명/권한/예외/T13을
  연결한다. 이를 upstream으로 재사용하고 별도 T19 저장·발급 경로는 만들지 않는다.
- NET-01.2/01.3은 DB/pooler 원문 둘 다 필요하다. 새 네트워크 집계 검증을 약화하지 않는다.
- T14 앱 격리는 실제 로컬 PostgreSQL 검증이 추가됐지만 AWS 객체의 양쪽 실제 접근은 미검증이다.
  EKS 별도 namespace의 Deployment TCP 정책 집행 성공은 이전 DB/pooler FAIL을 뒤집지 않는다.
- 수정: `PLATFORM_BASELINES`, 명시적 `baseline_sha`, 양쪽 source checkout/CI 소비 시험.
- 시험: 새 기준 실제 모듈/SQLite 15 PASS(6.17초). 기존 기준도 별도 유지한다.
- 원본 platform 폴더: 계속 `505d451`에서 수정 없음. 참조 checkout은 security의 무시된 개인 폴더에만 둔다.
- 상태: 계약 소비 검증. 플랫폼 개발이 계속되므로 이후 head의 자동 호환은 주장하지 않는다.

## SVC-05: 독립 실행·배포 준비·사고 관점 보강

- 요구: CTRL-01·02·06·07, SEC-PATCH-09·10, POL-01·03·10. 현재 기준 b19488e.
- 독립 프로세스: 실제 Python 서비스 프로세스 + TLS + 온라인 Ed25519 검증기 모형 +
  테넌트 고정 PG 역할의 연결/철회 포함 6 PASS(7.57초). 실제 Kubernetes 인증으로 확대하지 않는다.
- 배포 생성기: 명시한 digest·tenant·audience·주소/port로 JSON만 생성. non-root/read-only,
  최소 RBAC, SA 자동 mount 해제, NetworkPolicy와 제한 자원을 구성한다. apply는 하지 않는다.
- 사고 검토 중 원본 관측을 재수집할 때 heartbeat/finding 유효기간이 늘어날 수 있음을 발견했다.
  `team_detection.import_detection`의 만료를 원본 last_success/event 시각에도 결속했다.
  관련 단위 시험 31 PASS; 오래된 원본의 재수집으로 새 보안 근거를 만들지 않는다.
- 로컬 감사 파일에 16MiB 기본 상한을 추가했다. 가득 차면 기존 기록을 보존하며 신규 판정을 보류한다.
  이것은 감사 보관 정책/전체 PVC 용량 관리의 대체물이 아니다.

## SVC-06: 전체 증거 경로와 회귀 검증

- 요구: SEC-PATCH-05·10, CTRL-02·07, POL-03·09·11. 기준 b19488e/f602b39.
- 정상 서명 원본을 모두 채운 실행 시험에서 5초 기한 초과를 발견했다. 연결만 요청별로
  재사용하고 현재 원본을 묶음 검증하도록 수정했다. 공통 인증 callback의 tuple 반환 거부도
  실제 서비스 시험에서 발견·수정했다. [ADR-0003](../adr/0003-request-scoped-live-evidence.md)에
  설계와 실패 기록을 남겼다. callback 계약이나 만료·철회 검사는 완화하지 않았다.
- 코드: `review_connections`, `program_evidence`, `registered_program`, `security_program`,
  `review_service`, `review_server`. 실제 TLS/PG 서비스 7 PASS(10.44초).
- 전체 Linux PostgreSQL 17.11·OPA 1.22 회귀: security **775 PASS, 43.03초**;
  Sova **1,102 PASS, 3 SKIP, 107.56초**. 격리 DB를 만들고 시험 뒤 종료했다.
  Sova skip은 실제 컨테이너/Collector/등록된 AWS SQS 시험이다. 합성 클라우드 검증으로 세지 않는다.
- 증거: `tests/integration/test_review_host_runtime.py`, 단위 회귀, 개인 실행 로그
  `.local-notes/service-work/{security,sova-test}-pg-opa-tests.txt`.
- 배포 생성기 등 Windows 관련 시험: 46 PASS/1 POSIX 전용 SKIP. Linux 전체에는 해당 시험 포함.
- 현재 Docker 엔진 두 로컬 endpoint가 실행 중이지 않음을 확인했다. Kubernetes 명세 생성 시험은
  통과했지만 컨테이너 이미지 실행이나 실제 CNI/RBAC 차단의 증거로 사용하지 않는다.
- [22개 검사 대응표](../platform-control-traceability.md)를 추가했다. 6개 범주/하위 시험과
  추가 요구를 분리하고 부분적인 T14/T19 PASS를 전체 프로그램 인수로 확대하지 않는다.
- 상태: 로컬 실제 DB/TLS + 모의 권한/측정 검증. 운영 TokenReview·CNI·T24 인수는 남아 있다.

## SVC-07: 원격 CI의 엄격한 TLS 검증

- 최초 push `b3cbbe6`의 두 platform-contract 작업과 secrets 작업은 통과했다.
  Python 3.14 package에서 TLS 시험 8개가 실패했고 3.11 작업은 matrix fail-fast로 취소됐다.
- 원인: 시험용 인증서에 Authority Key Identifier와 엄격한 CA key usage가 없었다.
  Python 3.12에서 VERIFY_X509_STRICT를 켜 `Missing Authority Key Identifier`를 재현했다.
  [Python 공식 변경 설명](https://docs.python.org/3/library/ssl.html#ssl.create_default_context)에
  따르면 3.13부터 엄격한 검증이 기본이다.
- 수정: `tests/tls_review_support.py`의 일회용 CA/leaf를 올바른 X.509 확장으로 발급한다.
  생산 코드의 TLS 검증은 바꾸지 않는다. TLS wire 시험은 구버전 Python에서도 strict flag를 켠다.
- 상태: 로컬 TLS 회귀 후 원격 CI 재검증. 최초 실패는 통과로 집계하지 않는다.

### SVC-07 재검증 결과

`606623dd66bddbb64e8bfb0f96f62ab42dd92d96`의
[CI 실행](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42196071522)은
Python 3.11/3.14, 두 플랫폼 기준, secrets 모두 통과했다. Sova의
[고정 패키지 소비 CI](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42195818784)도 통과했다.
같은 security commit을 git archive한 별도 잠금 환경에서 wheel을 빌드·설치하고
Sova/bravo_gate 없이 import/CLI help와 pip check를 확인했다.
로컬 wheel SHA-256은 `86259bf30834cd0c7a41beb014db687d55b010efa71368d7fb4dbcd3006dc4ce`다.
이는 개인 빌드이며 정식 발행/서명된 릴리스가 아니다.

## SVC-08: 플랫폼부터 독립 보안 프로세스까지 연결

- 요구: SEC-PATCH-05·06·10, CTRL-01·02, POL-09·11. 기준 f602b39와 b19488e.
- 코드: `tests/platform_review_support.py`, `tests/review_runtime_support.py`,
  `tests/integration/test_platform_review_runtime.py`. 기존 fixture를 공유하도록 정리했다.
- 실제 T10/T19·SQLite 승인 → TLS 독립 프로세스 → SELECT-only PostgreSQL → 원본 Ed25519
  증거를 연결했다. T13/T14 측정과 TokenReview API, 외부 컷오버 실행기는 여전히 모형이다.
  시험 등록 행은 호스트의 동일 plan transaction에서 읽고 변경하는 시험 어댑터다.
  운영 플랫폼에 새 table을 설치한 것이 아니다.
- f602b39 연결 시험 10 PASS(58.65초), b19488e 연결+기존 실행 시험 17 PASS(63.05초).
  initial/post_apply 각각에서 승인 후 원본 issuer·서비스 등록·호스트 등록·workload 철회는
  외부 실행 0회이며 SHIFT를 유지했다. 정상 실행 후 응답 유실은 SAFE_HOLD와 POST 1회/GET 1회다.
- 최초 반복 실행은 같은 resource의 프로그램을 새 시각으로 재등록해서 anti-rebinding 검사가
  거부했다. 각 시험 resource ID를 분리했고 생산 코드의 보호를 바꾸지 않았다.
- GitHub CI의 격리 PostgreSQL socket과 Python 3.14의 고정 platform source를 연결해
  이 경로를 지속 시험한다. 클러스터/CNI/업무 데이터 인수 상태는 별개다.

## SVC-09: 실제 Kubernetes 인증·철회와 incident hold

- 요구: CTRL-01·02·04, POL-01·09·11, SG-1, SEC-PATCH-05. 기준 b19488e.
- 코드: `tests/kubernetes_api_support.py`, `test_kubernetes_review_identity.py`,
  `test_platform_review_runtime.py`, CI의 checksum 고정 envtest 설치.
- [ADR-0004](../adr/0004-local-kubernetes-authentication.md): 새 로컬 Kubernetes 1.35.0 API·etcd 3.6.6,
  실제 TokenRequest/TokenReview, 생성 명세의 RBAC만으로 시험한다. 기존 kubeconfig를 읽지 않는다.
- 단독 실제 API 5 PASS(23.96초). 실제 API와 T10/TLS/PG 묶음 17 PASS(107.00초).
  bound Secret 철회 10.023초, SA 철회 10.017초. JUnit 속성 2개에 관한 형식 경고는 이후
  속성 기록 실행에서 legacy JUnit을 명시했다. 인증/철회 실패를 경고로 무시한 것이 아니다.
- 이 전파 지연 때문에 다음 설계를 명확히 했다: 침해 시 기존 호스트 보류/승인 제한과 별도
  보안 hold를 먼저 적용하고 자격을 철회한다. 자동 hold 해제나 기존 앱 중단은 추가하지 않는다.
- 추가 실제 API/T10/PG 시험 2 PASS(11.88초). 삭제 직후 TokenReview가 두 번 모두 여전히
  성공했지만 current hold로 접수는 0.085/0.087초에 거부됐으며 외부 실행은 0회였다.
- 원격 `f98810c`의 [전체 서비스 체인 CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42197704724)는
  모든 작업 통과. 실제 API 추가분은 별도 commit/CI로 검증한다.
- 미검증: 팀 EKS/RKE2 배포판·CNI·Pod·실제 DB/Secret 연동, 운영 revocation 상한,
  host-side 보류 writer의 운영 배선, 이미 접수한 실행의 실환경 조정. 로컬 실측과 구분한다.

### SVC-09 CI 결과와 공개 checksum 오탐

- `051687a`의 Python 3.11/3.14 및 두 플랫폼 계약 작업은 통과했다.
  secrets 작업은 `tests/kubernetes_api_support.py:21`의 공개 kube-apiserver 바이너리
  SHA-256을 `generic-api-key`로 탐지했다. 토큰이나 키를 저장한 결과가 아니다.
- `.gitleaks.toml`에 해당 공개 digest의 정확한 값만 예외로 추가했다. 파일 전체,
  규칙 전체 또는 테스트 디렉터리를 제외하지 않는다. 전체 Git 이력을 다시 검사한다.
- 근거: 공식 SIG envtest v1.35.0 archive SHA-512 검증과 추출 바이너리 SHA-256 검증,
  CI run `42199949004`의 secrets 작업 및 마스킹된 로컬 이력 보고서.

## SVC-10: 세 번째 플랫폼 기준과 실제 T7 audience 경계

- 요구: CTRL-01·02, POL-01·09·11, SG-1, SEC-PATCH-05. 기준 `c225c86cf5e408b5fcd016b0e367d3672d1bac44`.
- `b19488e` 이후 10개 커밋은 console 초기 판정 표시·allowlist 기반 agent 관측·의존성 및
  설계 문서 변경이다. T10/T19 집행 코드의 변경은 없었다. 기준을 자동 추적하지 않고 세 SHA를
  명시하고 각 계약 CI를 유지한다. 사용자 platform 작업 사본은 변경하지 않았다.
- 전체 로컬 보안 시험: `SOVA_PLATFORM_SOURCE=<c225c86 checkout>`와 실제 PG/OPA/API를
  지정하여 **794 PASS, 153.31초**. 이후 추가한 T7/audience 시험은 **3 PASS, 4.47초**.
- 실제 T7 acquire는 API audience에서 성공하지만 보안 서비스가 해당 토큰을 거부한다.
  서비스 audience를 주면 T7의 최종 대상 SelfSubjectReview가 HTTP 401로 거부한다.
  [ADR-0005](../adr/0005-service-credential-audience.md)에 기존 Kubernetes projected token
  경로를 내부 소비자의 기본 방향으로 정했다. 새 issuer를 만들거나 두 audience를 합치지 않는다.
- 시험의 issuer 접근은 shim이며 Tailscale·kubelet 실환경 인수가 아니다. 외부 소비자를 위한
  T7 확장은 플랫폼 인계 사항으로 남긴다. 문서의 형식 호환 설명을 실제 동작에 맞춰 보완했다.
- `baba9ba` CI의 secrets 및 이전 두 계약/3.11은 통과했으나 3.14에서 서명 증거 전체 경로
  15개 시험이 실패했다(779 PASS). 로컬 통과로 덮지 않고 성능 계측을 이어간다. 공개 digest
  예외 추가는 서비스 동작을 바꾸지 않았다. 최종 원격 인수는 이 실패를 해결한 뒤 판정한다.

## SVC-11: 제한 시간 안의 현재 증거 검증

- 요구/설계/수정 코드는 [ADR-0006](../adr/0006-bounded-live-route-reads.md)에 기록했다.
  기준 c225c86, wire·DB schema 변경 없음. 고정 타입 정보만 재사용하고 현재 증거 경로를
  묶어서 조회한다. 5초 기한, 원본 서명, 조회 전후 철회·변경 검사는 유지한다.
- `5abc729` [원격 CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42202409928)는
  세 플랫폼 계약, Python 3.11/3.14, secrets 모두 통과했다. 이전 실패가 간헐적이라는 점과
  실제 반복 비용을 모두 기록하며 특정 CI 호스트 원인으로 단정하지 않는다.
- 같은 잠금 Python 3.14 계측에서 함수 호출 약 3,598만→1,122만, 계측 시간 9.618→2.967초.
  이는 프로파일러를 켠 수치다. 계측+PG 경계 묶음 32 PASS, 14.77초.
- `pytest tests/contracts/test_modernization_codec.py tests/unit/test_program_evidence.py -q`:
  64 PASS. 이후 실제 부모 철회 race 시험 3개를 추가했다.
- 잠금 Python 3.14 + c225c86 + 실제 PG/OPA/Kubernetes 전체: **826 PASS, 123.68초**.
  모의 공급자와 실제 인프라의 구분은 기존 SVC-08~10을 따른다. 원격 CI도 변경 커밋으로 재검증한다.

## SVC-12: 최소 입력의 서비스 이미지와 실제 컨테이너 검증

- 기준 c225c86. 요구·설계 이유·인수 경계는 [ADR-0007](../adr/0007-commit-bound-service-image.md).
- 코드: `deploy/security-review.Dockerfile`, `scripts/prepare_service_image.py`,
  `scripts/verify_service_image.py`, `tests/container_review_support.py`, CI `service-image`.
- source commit에서 wheel을 만들고 service extra만 해시 검증해 설치한다. 비밀이나 저장소 전체를
  Docker build context에 넣지 않는다. 기본 UID와 실제 연결 시험의 범위를 명시했다.
- 준비: 공식 base digest 조회, 잠금 runtime requirements 오프라인 export, 로컬 ruff/Git
  whitespace 통과. 실제 CI image build/TLS/철회 결과는 실행 후 보충한다.
- `a33863c` [전체 CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42203712045)
  모든 작업 통과. `sova-test`의 실제 2개 DB/독립 서비스 연결 8개 시나리오도
  [609d115 CI](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42205726034) 통과.
  전체 Sova 로컬 회귀는 1110 PASS / 3 SKIP이며 외부 컨테이너·collector·AWS 환경 인수는 별도다.

### SVC-12 결과 및 네 번째 플랫폼 기준

- `893ddff` [CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42207161356)는
  모든 작업 통과했다. 실제 이미지의 기본 UID 10001, 읽기 전용 root, capabilities 0,
  no-new-privileges와 service-only 의존성 9개를 확인했다. TLS/issuer 철회 1 PASS, 1.93초.
- 작업 중 develop은 `9e0d6a59d7a00925ddafc50cfa2ccad00c5ba768`로 8개 커밋 진행됐다.
  T13 실제 지문 기록, T9 ARM OpenBao pin, T43 GitOps image, T31 테스트 시계 변경이다.
  T10/T19 집행 코드 변경은 없다. 새 SHA를 네 번째 명시 기준으로 추가하고 기본값을 갱신했다.
- 새 기준 + 실제 PG/API의 계약·T10/TLS 체인·T7 시험: **32 PASS, 66.04초**.
  image job에도 새 기준의 initial/post_apply 정상·철회·단일 접수 10개 시나리오를 추가한다.
- [새 T13 실측](https://github.com/Softbank-Hackathon-Finals/platform/blob/9e0d6a59d7a00925ddafc50cfa2ccad00c5ba768/docs/evidence/t13-real-fingerprint-2026-11-06/README.md)은
  두 표 1행/2행의 데이터·스키마 MATCH다. 로컬 관리자·질의별 별도 트랜잭션이며 실제 실행기
  계정/동일 snapshot/시퀀스 보정/컷오버 인수가 아니다. 비공개 원본 digest도 없으므로 이 공개
  요약을 서명 원본으로 수입하거나 CTRL-06 전체 PASS로 바꾸지 않는다.

## SVC-13: 연동 토큰의 원래 수명과 단일 audience

- 기준 9e0d6a5. [ADR-0008](../adr/0008-service-token-use-boundaries.md)에 Salesloft Drift와
  NIST IR 8587 참고 근거, 실제 TokenReview의 교집합 동작, bearer 자격의 한계를 기록했다.
- 코드: `review_identity.py`, unit/integration identity 시험. 서비스 소비자만 단일 audience와
  원래 수명 600초를 요구하며 기존 TokenReview/UID/grant 확인을 유지한다. schema 변경 없음.
- `pytest tests/unit/test_review_identity.py -q`: **37 PASS**. 실제 Kubernetes API와 T7,
  최신 T10/TLS/PG 연결을 더한 잠금 Python 3.14 시험: **61 PASS, 85.04초**.
- API는 실제 발급한 복수 audience·3,600초 토큰을 각각 인증했다. 서비스는 둘 다 거부하고
  기존 600초 서비스 전용 자격은 허용했다. 전역 Kubernetes 토큰 정책이나 T7 코드는 변경하지 않았다.

## SVC-14: 실제 간접 DB 권한 우회 재현과 차단 조건

- 기준 9e0d6a5. [ADR-0009](../adr/0009-indirect-database-privileges.md)에 위협·선행 조건·관리자
  조치 경계를 기록했다. `review_database.py`, `review_server.py`, 실제 PG 회귀 파일을 수정했다.
- PUBLIC definer 함수와 owner-rights view로 다른 tenant의 합성 hold ID 읽기를 재현했다.
  직접 테이블 조회는 0행이었으나 기존 검사도 통과했다. 변경 전 새 시험은 2 FAIL이었다.
- 첫 수정은 PG17에 없는 large-object 검사 함수로 20 FAIL/27 PASS였다. 실제 catalog ACL
  검사로 수정한 뒤 DB 경계와 독립 TLS 서비스 묶음 **47 PASS, 19.73초**.
- 별도 관리자 PUBLIC 회수 후 직접 SQL도 거부되는 것을 확인했다. 서비스의 거부와 DB 자격의
  실제 권한 회수는 다른 동작이며, 서비스가 자동으로 팀 DB 권한을 변경하지 않는다.
- 플랫폼 DB와 같은 18.4의 공식 Docker index digest를 조회·확인해 image CI에 고정했다.
  기존 package CI의 PG17과 버전 간 동작을 대조한다. 결과는 해당 CI 이후 보충한다.
- `a78bac5` [토큰 보강 CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42208538564) 전체 통과.
  앞선 `97a6910` [image CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42207932376)도
  최신 플랫폼 initial/post_apply를 포함한 실제 컨테이너 연결 **11 PASS, 37.31초**였다.
- 잠금 Python 3.14 + 최신 플랫폼 + 실제 PostgreSQL/OPA/Kubernetes 전체 회귀:
  **847 PASS, 120.58초**. 새로운 간접 권한 검사와 토큰 수명 제한을 모두 포함한다.

### SVC-14 원격 결과

`269e1e5` [CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42209971176) 전체 통과.
PostgreSQL 18.4를 실제 버전 값으로 확인하고 DB 경계 **40 PASS, 11.07초**, 실제 이미지/T10
연결 **11 PASS, 36.04초**를 확인했다. 기존 PG17 package 및 네 플랫폼 계약도 통과했다.

## SVC-15: 소비 컨테이너의 permit 만료와 중복 원본 수집

- `sova-test d1865f3`의 process 소비는 통과했으나 container 소비는 4 FAIL / 35 PASS였다.
  모든 실패는 효과 실행 전 permit 만료 거부다. 원래 만료 시각을 29~92ms 넘겼으며 이를
  정상 효과나 인수 성공으로 기록하지 않는다.
- [ADR-0010](../adr/0010-current-collection-authentication.md)의 명시적 current-collection
  callback을 도입했다. 기존 callback 의미를 바꾸지 않고 현재 원본 재조회·서명 검증·전체
  collection 일치가 하나의 검증에서 보장될 때만 중복 수집을 제거한다. 정확한 True만 허용한다.
- 수정: `application/security_program.py`, `adapters/registered_program.py`, `program_evidence.py`.
  단위 시험 **98 PASS**, 실제 PG/TLS/계측 **17 PASS, 11.24초**.
- 계측에서 원본 수집은 5회에서 3회로 감소했다. 현재 함수 호출 약 713만/1.956초는 계측값이며
  운영 SLA가 아니다. 기존 permit/결과 5초 기한과 접수 직전 재검사를 유지한다.
- 잠금 Python 3.14 + 기준 플랫폼 + 실제 PG/OPA/Kubernetes 전체 회귀: **867 PASS, 115.02초**.

### SVC-15 소비 CI 결과

생산자 `2898f54`를 고정한 Sova `4987c24` [CI](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42212461099)
process/container 모두 통과. 실제 컨테이너 소비 **39 PASS, 31.89초**이며 앞선 네 만료 실패를 해소했다.
부하가 더 크거나 원본이 바뀔 때의 만료/철회 거부 조건은 그대로 유지한다.

## SVC-16: 느린 TLS 응답의 공통 기한과 부가 정보 제한

- 요구/설계/한계: [ADR-0011](../adr/0011-shared-http-network-deadline.md).
  변경 전 실제 응답 지연 및 큰 헤더 시험 4 FAIL을 확인했다.
- 수정: `adapters/deadline_http.py`, `review_https.py`, `tests/integration/test_review_deadlines.py`.
  DNS 반환 뒤 TCP/TLS/send/read 전체의 남은 시간을 공유하고 HTTP metadata 누적 한도를 적용한다.
  DNS 자체 취소나 운영 전체 기한을 보장한다고 주장하지 않는다.
- 실제 TLS 정상/거부 및 identity 관련 **58 PASS, 8.16초**. 전체 잠금 런타임과 원격 소비를 이어간다.
- 잠금 Python 3.14 + 실제 PG/OPA/Kubernetes + 최신 플랫폼 전체 회귀 **879 PASS, 117.93초**.
  앞선 current-collection 생산자 [CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42212375242)도
  Python 두 버전·플랫폼 네 기준·PG18 실제 이미지·secrets 모두 통과했다.

## SVC-17: 초기 제한된 DB 관리 함수 실행 권한

- [ADR-0012](../adr/0012-restricted-database-routines.md): 직접/PUBLIC grant 두 경우에 공개
  `PG_VERSION` 파일 읽기와 guard 누락을 실제로 재현했다. 변경 전 **2 FAIL**.
- `review_database.py`는 초기 ACL에서 PUBLIC 실행이 제한됐던 함수의 현재 EXECUTE를 거부한다.
  별도 관리자 REVOKE 후 직접 SQL도 거부된다. schema/wire 변경 없음.
- `test_review_database_admin_functions.py` 및 PG18 CI에 시험을 추가했다.
  실제 PG17 경계와 TLS 서비스 **49 PASS, 16.91초**. 전체/PG18 결과는 후속 기록한다.
- 잠금 Python 3.14 + 실제 PG/OPA/Kubernetes + 9e0d6a5 전체 회귀 **881 PASS, 117.78초**.

## SVC-18: 다섯 번째 플랫폼 기준과 T30 쓰기 개방 경계

- 원격 develop `a610bbfb60d3a633597d75dc6e070addd3c3b559` 확인. 이전 기준보다 6개 커밋:
  T43 Helm 복구/field conflict 처리, gate grant ConfigMap mount 보정, T30 APPLIED 뒤 쓰기 개방 helper.
  T10/T19 집행 코드 변경은 없다. 기본 기준을 갱신하고 앞선 네 SHA도 별도 소비 CI로 유지한다.
- 새 `open_after_apply.py`는 T31 기록을 읽고 기존 `write_switch.py`의 status/open을 한 번 호출하는
  운영자 helper다. marker가 있는 불명확한 실행은 재개방하지 않는다. 자체 보안 승인기를 추가한
  기능이 아니므로 우리 원격 보안 판정의 강제 집행으로 계산하지 않는다.
- 플랫폼 인계 때 **쓰기 개방·Edge 전환·컷오버도 같은 계획·반영 ID·이미지 digest·현재 상태에 결속**하고,
  직접 operator/kubeconfig 경로의 권한을 제한해야 한다. 기존 T10 승인이나 서비스 PASS만으로
  해당 수동 명령의 우회가 제거됐다고 주장하지 않는다. 별도 인수 항목으로 유지한다.
- 사용자 platform checkout은 수정하지 않고 소유한 격리 참조 복사본에서 계약/실행 시험을 수행한다.
- 새 기준에서 계약/실제 T10/TLS/T7 연결 **32 PASS, 60.51초**. upstream의 T30 helper 모의 시험도
  **7 PASS**였다. 후자는 실제 쓰기 개방이나 클러스터 권한 인수가 아니다.

## SVC-19: 실제 시간의 자격 수명과 프로세스 자원

- 요구/설계/한계: [ADR-0013](../adr/0013-owned-process-endurance.md).
  명시적으로 선택하는 실제 PG/TLS 독립 프로세스 endurance 시험을 추가했다.
- 180초 예비 시험 **1 PASS, 181.55초**. 정상 12회, issuer/grant 철회 각 6회, 실제 만료 거부 2회.
  파일 핸들 8개/스레드 2개 유지, RSS 증가 236KiB. 다음 단계는 13,200초 연속 관측이다.
- 정리 완료까지 확인해야 report를 completed로 기록한다. 정상 완료/실패 모두 자신의 프로세스와
  DB를 정리하며 민감한 자격이나 원본 데이터를 보고서에 넣지 않는다.
- DB 관리 함수 [CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42213904868)
  전체 통과: PG18.4 경계 **42 PASS, 11.39초**, 실제 이미지/T10 **11 PASS, 39.47초**.

## SVC-20: 실제 서비스 이미지 취약점 수집과 판정의 분리

- [ADR-0014](../adr/0014-service-image-vulnerability-evidence.md)에 수집/판정/배포 승인 경계를 기록했다.
  `scripts/scan_service_image.py`, 계약 시험, 실제 이미지 CI를 추가/수정했다.
- 공식 불변 Trivy 0.76.2 archive를 GitHub release digest로 검증해 executable 해시도 확인했다.
  별도 공개 DB·고정 로컬 이미지·실제 Python inventory를 결속하며 OS package도 검사한다.
- 계약 **21 PASS**. 0건 결과, 스캔 오류, UNKNOWN/BLOCK을 구분한다. repo digest를 만들어서
  기존 플랫폼 inventory/원본 계약을 우회하지 않으며 registry 발행은 수행하지 않는다.
- 앞선 `uv audit --frozen` service subset은 2026-11-06T11:21:30Z에 **10 packages, 알려진 취약점 0건**이었다.
  lock SHA-256 `8668d10143d6f24123a3aca54adad7052cbb40d547baa53ae21f96a4cded37ac`.
  대상은 Linux x86_64/Python 3.12.16 dependency 선택이며, 감사 도구가 실행한 interpreter는
  별개다. OS image 전체나 미래의 취약점 부재를 입증하는 결과가 아니다.

### 로컬 검증 중 저장 공간 소진 — 2026-11-06T12:15Z

- 새 scanner DB가 1,675,603,968 bytes로 내려받아지는 동안 Windows C:의 여유 공간이 소진됐다.
  WSL 내부 `df`의 가상 여유 공간만 확인한 것은 충분하지 않았다. 이후 Ubuntu에서 EIO/SIGBUS가 발생했다.
- 진행 중이던 전체 시험과 13,200초 endurance는 중단/실패다. 기존 881 PASS나 180초 예비 시험을
  이번 실행의 성공으로 대체하지 않는다. 장시간 보고서의 마지막 `running` 상태는 프로세스 사망 전 기록이며 완료 증거가 아니다.
- endurance 마지막 관측은 약 572초, 20 cycles, 정상 40회, issuer/grant 거부 각 20회, 만료 거부 16회다.
  이는 중간 관측일 뿐 통과 결과가 아니다. DB/프로세스 최종 정리도 확인되지 않았다.
- 기존 사용자 Bash/Redis 프로세스 때문에 Ubuntu 재시작은 사용자 승인 대기다. 전역 WSL 종료나
  파일시스템 수리는 수행하지 않았다. 새 대용량 로컬 다운로드를 중단하고 원격 CI로 검증을 옮긴다.
- 수집기에 native Linux/6 GiB 여유 공간 사전 조건을 추가했다. WSL VHD의 호스트 용량 오인을 피하며,
  이 조건도 실행 중 외부 공간 사용까지 보장하는 quota는 아니다. 계약 시험 **25 PASS**.

사용자가 약 4 GiB 공간 확보와 재시작을 승인한 뒤 **Ubuntu 배포판만** 재시작했다.
그 후 새 임시 파일의 읽기/쓰기/fsync와 기존 Python 3.14.10 실행을 확인했다.
기존 scanner 임시 경로에는 복구 후 예상 이름의 0바이트 파일만 남아 있었다. 경로·symlink 부재·
전체 항목 whitelist·파일 크기를 검사한 후 그 경로만 제거했다. 다른 배포판/사용자 자료는 정리하지 않았다.
Windows C: 여유 공간은 약 4.25 GB였다. 이전 중단된 시험은 계속 실패로 보존한다.
대용량 scanner DB는 로컬에 다시 받지 않으며, 새 소스 복사본에서 로컬 회귀를 준비한다.

### 원격 endurance 재시도

기존 CI에 별도의 PostgreSQL 18.4 / Python 3.14 endurance job을 추가했다. 개인 검증 브랜치의
push commit 메시지에 `[review-endurance]`가 있는 경우에만 10,800초 실행한다. 일반 push/PR은
장시간 작업을 생략한다. runner/DB는 격리되어 있고 보고서만 artifact로 올리며 fixture 자격은 제외한다.
실행 접수나 시작을 통과로 취급하지 않는다. 완료된 테스트와 보고서, 프로세스 종료를 확인해 후속 기록한다.

## SVC-21: 부분 감사 기록 이후의 신규 판정 보류

- [ADR-0015](../adr/0015-torn-local-audit-records.md): 저장 공간 장애에서 파생된 실제 결함이다.
  10 bytes 쓰기 후 ENOSPC를 주입했을 때 다음 감사 기록이 성공하는 조건을 **변경 전 1 FAIL**로 확인했다.
- `review_mounts.py`는 같은 fd의 마지막 줄바꿈을 확인하고 미완성 파일을 보존한 채 거부한다.
  전체 로그 재파싱이나 자동 삭제/절단을 추가하지 않는다. wire와 플랫폼 실행 계약은 유지한다.
- 시작된 3시간 CI는 `163111e` 소스의 관측이다. 이후 수정이 그 실행에 들어간 것으로 주장하지 않는다.
  이번 변경의 별도 단위/전체 CI 결과를 연결한다.
- Windows의 감사/서비스/ASGI 단위 시험 **52 PASS, 1 SKIP**. SKIP은 POSIX symlink/FIFO 시험이며
  Linux CI에서 별도 실행한다. Ruff와 diff 공백 검사를 통과했다.

## SVC-22: 실제 이미지의 잔존 installer 제거

- [첫 실제 이미지 검사](../evidence/service-image-scan-2026-11-06/README.md)는 수집 성공,
  정책 **BLOCK**이다. HIGH 49 finding / 13 고유 CVE, MEDIUM 80, LOW 63, CRITICAL 0.
  OS 87개와 서비스 venv 10개를 확인했고 venv 밖 기본 pip의 취약점 6개도 발견했다.
- build installer는 기존 uv.lock의 pip 26.2.2 wheel hash로 고정한다. runtime 이미지에는
  설치가 필요 없어 기본 pip/ensurepip를 제거하고 global site-packages와 entrypoint 부재를 검사한다.
  원본 보고서는 수정하지 않으며 새 이미지의 재스캔 결과와 구별한다.
- OS HIGH는 미수정 상태다. Debian 1차 자료와 함께 인수 문서에 기록하고 배포 BLOCK을 유지한다.
  현재 격리 통제나 일반 CI 통과를 해당 CVE 해결로 간주하지 않는다.
- 공개 scanner 원본을 보존한 `5c4e0f5`의 Gitleaks가 2개 항목을 거부했다. 이를 바로 예외 처리하지 않고
  규칙/파일/줄만 출력하는 실패 진단을 추가해 위치를 확인한다. 탐지 내용이나 credential은 출력하지 않는다.
- 두 탐지는 `scan.json` 55/149행의 공식 Python 이미지 **공개 서명 키 fingerprint**였다.
  [공식 Dockerfile](https://github.com/docker-library/python/blob/master/3.12/slim-trixie/Dockerfile)의
  GPG_KEY와 정확히 대조했다. 그 값 하나만 literal allowlist에 추가하고 모든 탐지 규칙/전체 history 검사는 유지한다.

## SVC-23: 감사 이후 최종 권한 확인

- [ADR-0016](../adr/0016-authority-after-review-receipt.md): 감사 기록 동안 근거 삭제·신뢰 철회·보류 추가가
  발생하는 세 시험이 변경 전 **3 FAIL**이었다. 기존 감사 후 검사는 신원/등록만 확인하던 틈이다.
- `SecurityProgramService`의 마지막 현재 원본 검사를 receipt callback 뒤로 옮겼다. 별도 collection이나
  cache를 추가하지 않는다. callback 없는 기존 직접 소비는 그대로 동작한다.
- endpoint는 정확히 한 번 기록한 report digest를 확인하고 같은 report를 반환한다. 원래 reviewed_at과
  최대 5초 기한을 유지한다. 시간 경과로 판정이 달라지면 새 PASS를 만들지 않고 거부한다.
- Windows 단위 전체 **740 PASS, 6 SKIP, 10.02초**. SKIP은 POSIX OPA 프로세스 5개와 symlink/FIFO 1개다.
  실제 PG/TLS에서 독립 writer의 verifier 철회/hold commit 시나리오를 추가했다.
  전체 Linux CI와 T10/Sova 소비 결과는 후속 기록한다.

## SVC-24: 여섯 번째 플랫폼 기준과 운영 결과의 의미

- 2026-11-06T12:51Z 원격 develop은 `8b12236ae4277de16cebdf1391f87721e5851d47`이다.
  a610bbf 이후 24개 commit을 비교했고 T10/T19 집행 코드는 바뀌지 않았다.
  기본 기준·전체 서비스 CI·실제 이미지 소비를 갱신하고 이전 다섯 기준의 계약 시험도 유지한다.
- T7 object operations는 API audience와 별도 서비스 audience를 사용하며 기존 인증 경로를 재사용한다.
  새 issuer를 만들 이유가 줄었다. 다만 이 서비스의 audience/owner/권한을 보안 서비스와 공유하지 않는다.
  기존 T7 acquire의 SelfSubjectReview 제약은 그대로이고 외부 보안 소비자 연결은 별도 인수다.
- object `open`은 개발용 익명 읽기를 명시적 close까지 유지한다. **작업 FINISHED/PASS/CLEAN이
  security PASS 또는 닫힘을 뜻하지 않는다.** final_state=open/security_state=PUBLIC_READ는
  보안 통제에서 별도로 다뤄야 하며 이 운영 API의 결과를 22개 검사 PASS로 변환하지 않는다.
- T15 host chart는 기존 저장 제안·T10 intake·T7 manager/runner를 연결하며 기본 비활성이다.
  manager admission 정책과 runtime 네트워크/Secret/PVC 공급을 보안 서비스가 대신 설치하지 않는다.
  record_key의 임시 Secret은 T9/OpenBao 인계 대상이며 우리 쪽 별도 키 발급기를 추가하지 않는다.
- 새 T14 소스/배포 명세 실측은 양쪽 **SEC-01.2 1 PASS / 나머지 19 UNKNOWN**이다.
  이전 TLS 실행과 합쳐 단일 통과 결과를 만들지 않는다. T21 출처 유효기간 표시도 원본 기한을 보존한다.
- 현재 기준의 계약/T10/T7/컨테이너 CI를 실행하고 결과를 후속 기록한다. 운영 클러스터에는 접속하지 않았다.

근거: [변경 비교](https://github.com/Softbank-Hackathon-Finals/platform/compare/a610bbfb60d3a633597d75dc6e070addd3c3b559...8b12236ae4277de16cebdf1391f87721e5851d47),
[object API](https://github.com/Softbank-Hackathon-Finals/platform/blob/8b12236ae4277de16cebdf1391f87721e5851d47/docs/object-operations.md),
[T15 host](https://github.com/Softbank-Hackathon-Finals/platform/blob/8b12236ae4277de16cebdf1391f87721e5851d47/infra/charts/rehearsal-host/README.md),
[T14 실측](https://github.com/Softbank-Hackathon-Finals/platform/blob/8b12236ae4277de16cebdf1391f87721e5851d47/docs/evidence/t14-dual-source-scan-2026-11-06/README.md).

## SVC-25: 실제 OS 인벤토리와 scanner 범위의 대조

- installer 제거 후 [원본과 결과](../evidence/service-image-scan-2026-11-06/README.md)를 별도로 보존했다.
  pip finding 6건 제거를 확인했으며 OS HIGH 49건 때문에 BLOCK은 유지한다.
- v2 수집 정책은 실제 컨테이너 `dpkg-query`의 설치 name/version/architecture 전체와 scanner의
  OS package 집합이 같아야 한다. Python package 집합도 venv와 같고 global installer가 없어야 한다.
  OS result 하나만 존재하거나 일부 라이브러리가 누락된 결과를 충분한 검사로 취급하지 않는다.
- 실제 컨테이너 검증 스크립트와 scanner 계약 시험을 수정했다. Windows 계약 **32 PASS**.
  CI summary에 정책 BLOCK/PASS/UNKNOWN과 finding 수를 직접 표시해 수집 성공과 배포 판정을 구분한다.
- 앞선 receipt 변경 `4283346`의 Linux 전체는 **913 PASS, 1 SKIP, 153.04초**였다.
  SKIP은 명시적으로 별도 실행하는 endurance다. 현재 원본 변경과 여섯 번째 플랫폼 기준은 별도 CI로 검증한다.
- 첫 v2 [CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42221842328)는
  전체 기능/6개 계약은 통과했지만 image coverage에서 거부됐다. Trivy의 `Version`은 전체 Debian 버전이
  아니라 `Epoch`/`Release`와 분리된 구성요소였다. 원본과 실제 dpkg 목록을 대조해 확인했다.
  고정 scanner schema대로 binary epoch/upstream/revision을 재구성하며 source 버전이나 `+bN`을 버리지 않는다.
  잘못된 epoch·revision·architecture·누락 거부 조건은 유지하고 계약 시험을 **40 PASS**로 확장했다.

### SVC-25 결과와 복구 후 전체 회귀

- `d9c878f` [CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42223422299) 전체 성공.
  Python 3.14 **928 PASS / 1 SKIP, 150.66초**, 여섯 플랫폼 기준, PG18.4 **42 PASS**,
  실제 서비스 이미지/T10 **11 PASS**. SKIP은 별도 opt-in endurance다.
- v2 실제 inventory는 OS 87개/Python 10개 모두 일치했다. 원본은
  [증거 디렉터리](../evidence/service-image-scan-2026-11-06/README.md)에 보존한다.
  이미지의 미수정 HIGH 49건은 그대로이며 기능/수집 성공과 배포 BLOCK을 구분한다.
- 사용자 승인 Ubuntu 복구 후 새 참조 checkout과 검증 복사본으로 실행한 로컬 Python 3.14 전체는
  **928 PASS / 1 SKIP, 133.32초**였다. 실제 격리 PG17/TLS/OPA/Kubernetes API 및 platform 8b12236을 사용했다.
  앞선 SIGBUS 중단은 실패로 남긴다. 이번 시험은 scanner DB를 내려받지 않았다.
- 플랫폼 T15 발행의 `ignore-unfixed: true`를 이 서비스에 복사하지 않는다. 기존 OCI/digest 발행 경로의
  재사용과 취약점 정책의 호환은 별도 조건이며 현재 BLOCK을 자동 예외 처리하지 않는다.

## SVC-26: 같은 DB 서버의 다른 데이터베이스 접속 제한

- [ADR-0017](../adr/0017-database-specific-reader-ingress.md). 현재 RLS/권한 검사는 현재 DB 범위다.
  같은 로그인으로 다른 DB의 PUBLIC canary를 읽을 수 있음을 실제 private PG에서 재현했다.
- 운영자 전용 `reader_hba_rules`를 추가해 정확한 DB/reader/CIDR/TLS/SCRAM만 허용하는 규칙을 렌더링한다.
  다른 DB·평문·등록되지 않은 주소를 거부한다. 기존 서비스 API·T10 계약·reader DDL은 바꾸지 않는다.
- 로컬 PostgreSQL 17.11 실측과 단위 **31 PASS, 0.55초**. 최초 시도는 단위/통합 파일명 충돌로
  collection error였고 이름을 분리해 해결했다. 격리된 PG18.4 CI에도 TLS와 실제 접속 시험을 추가한다.
- 실제 HBA는 변경 전 bytes로 복구했다. 기존 열린 연결은 reload 뒤에도 살아 있음을 확인했으므로
  즉시 철회로 표현하지 않는다. 기존 host hold + 별도 자격/세션 철회 순서를 유지한다.
- CNPG 고정 규칙/사용자 규칙 순서, pooler와 Unix socket의 다른 경계는 별도 인수다.
  팀 Cluster나 공유 PUBLIC 권한을 변경하지 않았다. 실제 IPv6 연결과 CNPG CNI는 미검증이다.

### 복구 후 최신 receipt 코드의 지속 시험

- 실제 로컬 PG17/TLS 프로세스 **180초, 1 PASS, 181.50초**.
  6회 회전, PASS 12회, issuer/grant 거부 각각 6회, 이전 credential 실제 만료 거부 2회.
  RSS 58,984→59,312 KiB, descriptor 8/thread 2 유지, 본인 child 종료 확인.
- 원본 report의 모든 Python source와 시험 파일 해시가 `d9c878f`와 같음을 확인했다.
  [원본과 해석](../evidence/review-endurance-2026-11-06/README.md).
  별도 3시간 CI는 이전 source의 시험이므로 결과를 소급 합치지 않는다.

### SVC-26 CI 결과

- `b9f4f52` [CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42226489791) 전체 성공.
  PG18.4 기존 경계 **42 PASS, 11.79초**, 새 실제 TLS/HBA **1 PASS, 0.43초**,
  실제 image/T10 **11 PASS, 30.70초**. 이미지 스캔은 HIGH 49건으로 BLOCK 유지.

## SVC-27: 일곱 번째 플랫폼 기준과 진행 주체 확인

- 원격 develop `bb174860bedf100de3970c3e8e410f02f23994e2`는 8b12236보다 13 commit 진행됐다.
  새 `WorkflowHost`/`StageReaders`를 검토하고 현재 기본 기준·전체/이미지 CI와 계약 matrix를 갱신한다.
- 새 호스트는 상태별 판독기를 선택하고 미연결 단계는 보류한다. 준비 네트워크 읽기는 plan lock 밖에서
  plan/version별로 수행하며 실제 판독은 lock 안이다. 운영 조립은 아직 단계별 인수 대상이다.
- SHIFT는 이 드라이버의 진행 대상이 아니다. 기존 T10 실행 접수 책임과 `T10ProgramAuthority`를 유지한다.
  새 host가 SHIFT를 직접 실행하지 않는지, prepared reader를 다른 version/두 번째 호출에 재사용하지 않는지
  실제 고정 모듈로 계약 시험을 추가한다. 과거 여섯 기준에는 모듈이 없어 그 시험만 명시적으로 skip한다.
- 보안 서비스의 원래 5초 기한과 현재 호스트 승인/등록 재검사를 유지한다. 새 preparer가 네트워크 결과를
  받았다는 이유만으로 실행 허가를 만들지 않는다. T10 gate adapter를 모든 workflow state에 끼워 넣지 않는다.
- T19 정정은 양쪽 앱 경로가 같은 출발지 DB를 사용했음을 명시한다. 과거 기록을 독립 DB 일치로 해석하지 않는다.
  새 목적지 직접 수집은 단일 수집기 자격이며 복제 권한을 가진 기존 역할을 사용했다. 최소 권한 운영 인수와 다르다.
- T22 실제 브라우저 8조합 재접속은 클라이언트 연결 종료 시험이다. DB 컷오버·쓰기 개방·독립 목적지 운영의
  증거로 확대하지 않는다. 최종 기능·DB 신원·경로별 TLS는 같은 현재 승인 창에서 새로 수집한다.
- 로컬 전체 회귀 도중 host C: 여유가 약 0.82GB까지 줄어 본인 pytest만 SIGINT로 중단했다.
  이 실행은 미완료이며 통과로 집계하지 않는다. 별도 PG는 helper 정리 경로로 종료하고 CI에서 검증을 이어간다.

근거: [변경 비교](https://github.com/Softbank-Hackathon-Finals/platform/compare/8b12236ae4277de16cebdf1391f87721e5851d47...bb174860bedf100de3970c3e8e410f02f23994e2),
[워크플로 결정](https://github.com/Softbank-Hackathon-Finals/platform/blob/bb174860bedf100de3970c3e8e410f02f23994e2/docs/adr/0031-workflow-host.md),
[T19 정정](https://github.com/Softbank-Hackathon-Finals/platform/blob/bb174860bedf100de3970c3e8e410f02f23994e2/docs/evidence/t19-direct-database-2026-11-06/README.md),
[T22 범위](https://github.com/Softbank-Hackathon-Finals/platform/blob/bb174860bedf100de3970c3e8e410f02f23994e2/docs/evidence/t22-live-reconnect-2026-11-06/README.md).

## SVC-28: DB 연결 전 TLS·단일 경로 검증

- [ADR-0018](../adr/0018-validate-database-routing-before-connect.md). 기존 접속 후 TLS 검사만으로는
  잘못된 평문/prefer/mixed-host DSN이 DB 클라이언트에 먼저 전달될 수 있었다. 네트워크 없는 재현 **3 FAIL**.
- 정식 libpq parser 뒤 단일 host/port/DB/reader, TCP verify-full/절대 CA, private socket 조건을
  연결 전에 검사한다. 환경 service/hostaddr 우회와 TLS 대신 GSS 선택을 막는다. 실제 연결 후 검사도 유지한다.
- 기존 T9 mounted credential 회전과 readonly/statement timeout/search_path는 그대로다.
  관련 단위 **32 PASS / 1 SKIP**. 실제 PG18.4/HBA와 전체 서비스 CI로 연결 경로를 재검증한다.
- 직전 `1bfb877`의 일곱 플랫폼 기준·전체 package·image CI는 모두 성공했다.
  새 네트워크 전 검사는 별도 결과로 기록한다. 로컬 대규모 회귀는 C: 공간 때문에 계속 CI로 대체한다.

### 최신 구현의 별도 90분 CI 지속 시험

감사 이후 권한 확인·연결 전 TLS 검증까지 포함한 새 source를 더 길게 관찰하기 위해
`[review-endurance-90m]` opt-in을 추가한다. 기존 `[review-endurance]`의 3시간 실행은 그대로 유지한다.
명시적 marker가 없는 push/PR에서는 둘 다 실행하지 않는다. 같은 실제 PG18.4/TLS/별도 child 시험을
5,400초 수행하고 공개 측정 report만 보존한다. 이전 10,800초 실행과 소스·시간·결과를 구분한다.

## SVC-29: wheel 소비 근거의 최신 계약 목록 유지

- main wheel manifest의 필수 검사 목록이 과거 네 플랫폼 기준에 머물러 있음을 확인했다.
  `PLATFORM_BASELINES` 전체에서 생성하도록 바꾸고 3.11의 모든 브랜치에서 manifest 생성을 검증한다.
  wheel artifact 업로드는 기존 main push 조건을 유지한다. 별도 레지스트리 게시나 main 병합은 하지 않는다.
- 브랜치별 동명 0.11.0 wheel을 혼동하지 않도록 전체 source SHA·lock/wheel hash 인수를 안내한다.
  이미지 수집 CI 성공과 취약점 BLOCK을 구분하며 README의 운영 사용을 암시하는 첫 문장도 정정했다.

### SVC-27~29 최종 소비 기준 검증

- `f25433a3905737c97e8aab3a6ced6832c8d6d7eb`
  [CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42229814068) 전체 성공.
  Python 3.14 **983 PASS / 2 SKIP, 154.27초**. skip은 별도 opt-in endurance 및 CA 등록형 HBA다.
  HBA는 같은 실행의 PG18.4 image job에서 **1 PASS, 1.11초**로 별도 검증했다.
- PG18.4 기존 권한 경계 **42 PASS, 8.66초**, 실제 image/T10 **11 PASS, 27.88초**.
  최신 bb17486 계약 **18 PASS, 6.14초**, 나머지 여섯 기준과 Python 3.11도 성공했다.
- v2 이미지 수집은 성공했지만 **HIGH 49 / MEDIUM 75 / LOW 62, BLOCK**이다.
  ADR의 오래된 검증 중 표시를 확인한 수준으로 갱신하고 운영 인수 전 조건은 유지한다.

## SVC-30: 인계 상태 정리와 복구 거버넌스 대조

- [인계 현황](../platform-handoff-status.md)에 구조·요구사항별 구현/미검증 조건·고정 SHA·CI·운영 연결 순서를 모았다.
  팀 플랫폼 코드는 변경하지 않았으며 실제 계정/CNI/T24/백업 인수 전 조건을 별도로 남긴다.
- Asahi의 2026년 공식 후속 조사와 내부통제 약점 공시를 기존 복구·권한 경계에 대조했다.
  [사고 조사](../incident-research-2026-11-06.md)에 사실과 설계 판단을 분리했다. 이미 구현한 시험을
  이 사고의 재현으로 주장하지 않는다. Nikkei 공식 본문은 재시도에서도 접근되지 않아 구체 주장은 보류한다.
- 코드 변경 없이 확인된 ADR 상태를 정리한다. 장시간 CI는 기존 source별로 계속 실행 중이며
  결과 원본을 받은 뒤 해당 기록에 추가한다.

## SVC-31: 여덟 번째 플랫폼 기준과 T19 현재 키 원장 연결

- develop `98885a69999398bfe3f49fbc8324a7b19aae3e16`은 bb17486보다 16 commit 진행됐다.
  새 PlanAuthorityKeys·T28 운영자 도구와 기존 증거 정정을 검토하고 기본 SHA/CI matrix를 갱신한다.
- T19 공개키 원장을 기존 StoredGateServices/Ed25519Authority와 같은 계획 view로 연결했다.
  별도 manager가 공개키를 등록하고, 승인 이후 run-target 키를 폐기하면 initial/post_apply 모두
  추가 서비스 호출/외부 dispatch 전에 거부된다. 긍정 대조군은 POST 1회 후 GET 조정만 수행한다.
- 격리된 pinned platform/실제 SQLite/Ed25519 계약 **22 PASS, 7.31초**. 최초 4 FAIL은 시험 조립에서
  개별 보안 보고서를 combined report 자리에 넣은 오류였다. 두 보고서와 원래 서명을 구분해 수정했다.
  플랫폼 구현이나 운영 키는 변경하지 않았다. 과거 일곱 기준에는 새 키 원장 시험만 명시적으로 skip한다.
- [T28 재현](../evidence/t28-restart-boundary-2026-11-06/README.md)은 결과 기록 전 중단 뒤 재시작 시
  모의 효과가 1→2회임을 보였다. 실제 명령 0회이며 플랫폼 T10 원장의 결함으로 확대하지 않는다.
  현재 운영자 JSONL을 집행 정본으로 연결하지 않고 기존 T10/T31 영속 접수/조정을 인계 조건으로 남긴다.
- 정식 CI의 여덟 기준·전체·이미지 검증 후 Sova pin을 갱신한다. 진행 중 장시간 시험은 이전 source이며,
  새 baseline 허용 목록/계약 시험을 소급 검증한 것으로 기록하지 않는다.

## SVC-32 조사 시작: reader의 TEMP·대형 객체 생성 권한

- 테이블 SELECT/RLS 검사가 DB의 기본 PUBLIC TEMP와 대형 객체 생성 함수까지 막는지는 별도 문제다.
  공식 PostgreSQL 18 privilege/large-object 문서를 대조하고 실제 사설 DB 재현 네 경우를 추가한다.
- 시험은 각기 임시 테이블 또는 0~1 byte 대형 객체 하나만 만든 뒤 transaction rollback/역할 정리한다.
  기대하는 거부가 현재 구현에서는 실패할 것으로 예상하여 **strict xfail**로 명시했다. XFAIL은 보안 통과가 아니다.
  원격 결과를 확인한 뒤 전용 DB의 운영자 준비 조건과 runtime drift 검사를 함께 보강한다.
- 로컬 C: 여유가 다시 약 0.81GiB여서 DB 재현은 원격 CI에서 수행한다. 큰 로컬 회귀·DB 다운로드를 재개하지 않는다.

### SVC-32 구현 및 검증 접수

- 재현 source `a399357a1e8c9a553df22abaa1974319775fa2c8`의
  [CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42236129303)는
  Python 3.14 **987 PASS / 2 SKIP / 4 XFAIL**, PG18.4 **42 PASS / 4 XFAIL**이다.
  `-rx` 로그는 예상 실패 이유만 표시하므로 네 경우의 정확한 예외를 입증하는 traceback으로 해석하지 않는다.
  수정 후에는 xfail을 제거하여 실제 권한 거부 및 정상 서비스 동작을 모두 요구한다.
- ADR-0019에 전용 DB의 운영자 준비 SQL과 공유 DB에 대한 적용 조건을 기록했다.
  PUBLIC TEMPORARY와 세 대형 객체 생성 함수 권한을 회수하고 runtime 시작/종료에서 재검사한다.
  직접 및 PUBLIC 재부여 8가지와 실제 작업 거부 4가지를 검증한다. 운영 DB에는 적용하지 않았다.
- SQL 렌더링/시스템 DB 거부 단위 **9 PASS, 0.23초** 및 변경 Python ruff 통과.
  실제 DB 전체 회귀는 다음 원격 CI 결과로 판정한다. 신규 `[review-endurance-30m]`은 같은 실제 서비스
  시험을 1,800초 실행하며 진행 중 3시간/90분 결과를 대체하거나 취소하지 않는다.

### SVC-32 실제 수정 전후 대조

- C: 공간이 약 4.07GiB로 회복된 것을 확인하고 하나의 본인 소유 PG17.11만 잠시 시작했다.
  두 고정 Git source를 따로 추출한 `--runxfail` 결과는 수정 전 **4 FAIL / 0.35초**이며
  모두 `DID NOT RAISE InsufficientPrivilege`다. 설정 오류가 아니라 생성이 거부되지 않은 경우다.
- 수정 후 **12 PASS / 0.66초**, 임시 클러스터 종료를 확인했다. 실제 출력·source·해시는
  [수정 전후 근거](../evidence/reader-storage-2026-11-06/README.md)에 보존한다.
  기존 사용자 프로세스·DB에는 접근하지 않았고 일반 패키지 설치도 바꾸지 않았다.

### SVC-32 원격 회귀 결과

- `5ddf281` [CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42238259304)의
  Python 3.14 **1,008 PASS / 2 SKIP, 160.59초**, 3.11 **962 PASS / 48 SKIP, 56.00초**.
  3.11은 기본 호환성 실행이며 실제 플랫폼/외부 등록 fixture는 3.14 및 별도 job에서 검증한다.
- 여덟 플랫폼 계약, PG18.4 권한 **54 PASS / 11.34초**, TLS/HBA **1 PASS / 0.45초**,
  실제 image/T10 **11 PASS / 32.81초**가 통과했다. 같은 run의 30분 지속 job은 아직 관찰 중이다.
- 이미지 전체 재고는 OS 87/Python 10이며 **CRITICAL 0 / HIGH 49 / MEDIUM 75 / LOW 62,
  BLOCK, release_authorized=false**다. 원격 CI 성공을 운영 배포 허가로 쓰지 않는다.

## SVC-33: 직접 DB 로그인에도 연결 수 예산 적용

- HTTP/worker 제한과 탈취한 DB 자격의 직접 연결은 다른 경계다. 기본 무제한 역할 대신
  reader 생성 SQL에 기본 16/명시적 1~64 상한을 두고 runtime에서 무제한·차단·초과 drift를 거부한다.
  기존 발급·역할 생성 helper와 현재 권한 검사를 확장하며 새 네트워크 프록시는 만들지 않는다.
- Windows 단위 **9 PASS / 0.23초**, 실제 격리 PG17.11에서 연결 상한/회복·drift·기존 storage
  회귀 **25 PASS / 1.34초**. 기존 사용자 DB/프로세스를 사용하지 않았으며 owned PG를 종료했다.
  자세한 선택·근사 상한·공유 역할의 운영 예산은 ADR-0020에 기록했다.
- PG18.4 경계 CI에 네 실제 연결 시험을 추가한다. 최신 source의 별도 30분 지속 시험을 접수하며
  진행 중인 세 실행은 그대로 유지한다. 이전 source의 결과와 새 source의 검증은 분리한다.

## SVC-34: 아홉 번째 플랫폼 기준과 영속 공개 서명

- 15:10 UTC 확인한 develop은 `7edab5312f965bd683a7738e74d49b883190e8da`이며 이전 98885a6에서
  49 commits/116 files 진행됐다. 변경 이력의 T42 exec 추가와 후속 revert를 구분하여 최종 tree를 검토한다.
- 주요 연결은 T19 `PlanAuthorityRecords`의 공개 서명 저장/현재 재조회, T10 단계별 드라이버,
  최초 제안의 플랫폼 Job 경로, T14 분석기 자격 사전 검사와 T15 전용 admission 예외다.
  새 발급기/서명 서버/집행 엔진을 만들지 않고 기존 담당 경로를 소비한다.
- 기존 T10/T19 승인·실행 계약 22개가 그대로 통과했다. 새 실제 SQLite/Ed25519 시험은 두 단계에서
  서명 publish 재시도, 새 인스턴스 조회, 원래 20초 만료 보존, 키 철회/만료 후 거부를 확인한다.
  네 초기 실패는 합성 run을 먼저 등록하지 않은 시험 준비 오류였다. 실제 GateRecords 순서를 보완한 뒤
  전체 **26 PASS / 8.33초**. 운영 과거 관측을 새 키로 소급 인증한 시험이 아니다.
- 새 host의 REHEARSE는 기존 승인된 T31 적용, GATE는 실제 APPLIED 이후 재검사이며 SHIFT는
  여전히 운영자 접수 소유다. WATCH는 T36/T19 둘 다 PASS를 요구한다. 모든 단계 구현과 실제
  배포 ports의 인수 완료는 구분한다. 기존 T28 JSONL 재시작 경계의 인계 조건도 유지한다.
- T19의 양쪽 직접 DB 후속 원문은 같은 검증 문맥·겹치는 30초 창에서 서로 다른 CNPG의 두 schema/PK가
  일치한 새 관측이다. 이미 만료됐으며 운영 T10 신뢰 등록·전체 T19 PASS·데이터 행 검증으로 쓰지 않는다.
- 아홉 기준 CI와 기본 image/T10 source를 갱신한다. 진행 중 68ec731 지속 시험과의 runtime 차이는
  platform_review 기준 목록/기본 SHA이며 실제 계약은 새 CI에서 별도 확인한다.

### SVC-34 전체 CI의 정리 교착과 수정

- `b859233` [CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42241165698)의
  아홉 계약 job은 통과했지만 전체 3.14는 **1 FAIL / 1,024 PASS / 2 SKIP, 149.76초**였다.
  실패는 workload 철회 시험 본문 이후 임시 reader의 `DROP OWNED`와 PostgreSQL
  `autovacuum: ANALYZE sova_control.signed_security_evidence` 사이의 catalog 교착이다.
- fixture 정리만 독립 transaction으로 묶고 DeadlockDetected일 때 최대 3회 재시도한다.
  생성한 reader 이름 두 prefix/UUID 형태와 autocommit 연결만 허용하고 다른 오류는 즉시 실패한다.
  앱 실행·판정·시험 본문을 재시도하지 않고 autovacuum도 끄지 않는다. 단위 **7 PASS / 0.24초**.
- 제품 `src`는 변경하지 않았다. 같은 전체 회귀·PG18.4·실제 image/T10을 다시 확인한 뒤 Sova pin을 확정한다.

### SVC-33 원격 검증 결과

- `68ec731` [CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42240519877)의
  Python 3.14 **1,021 PASS / 2 SKIP, 158.53초**. 실제 PG18.4 권한 **58 PASS / 13.29초**,
  HBA **1 PASS / 0.44초**, image/T10 **11 PASS / 37.59초**. 여덟 플랫폼 계약도 성공했다.
- 아홉 번째 플랫폼의 계약은 별도 b859233 CI에서 **26 PASS / 11.84초**였다. 그 run 전체의
  fixture 정리 실패는 앞 기록대로 유지하며, 수정 후 재검증 source는 `ec4aac6`이다.

### SVC-34 최종 소비 기준 검증

- `ec4aac6c3d839111f76ef7466f7b6fc7fcea1e49`
  [CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42242142761) 전체 성공.
  Python 3.14 **1,032 PASS / 2 SKIP, 141.46초**, 아홉 플랫폼 계약 성공.
  실제 PG18.4 권한 **58 PASS / 9.26초**, HBA **1 PASS / 0.50초**, image/T10 **11 PASS / 25.63초**.
- Sova `5415fca` [CI](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42242378539)는
  process **44 PASS / 66.32초**, container **44 PASS / 39.86초**. 고정 producer/아홉 baseline과
  기존 두 DB·TLS·승인·원장·보류의 소비 경계가 일치한다. 플랫폼 작업 트리는 변경하지 않았다.
- 이미지 정책은 HIGH 49건 때문에 계속 BLOCK이다. 실측 이미지의 linux/amd64 범위와 ARM64
  별도 인수 필요를 명시했다. 계약/순수 Python의 호환성을 모든 노드 이미지 호환으로 확대하지 않는다.

## SVC-35: 완료된 지속 시험의 원본 보존

- 3시간 `163111e`: 실제 10,800.001초, **1 PASS / 10,802.96초**. 360회 회전, 정상 720,
  issuer/grant 거부 각각 360, 만료 거부 356, RSS 62,108→62,620KiB.
- 90분 `c4730bb`: 실제 5,400초, **1 PASS / 5,401.77초**. 180회 회전, 정상 360,
  issuer/grant 거부 각각 180, 만료 거부 176, RSS 62,848→63,352KiB.
- 저장 생성 제한 30분 `5ddf281`: 실제 1,800초, **1 PASS / 1,801.61초**. 60회 회전, 정상 120,
  issuer/grant 거부 각각 60, 만료 거부 56, RSS 62,804→63,204KiB.
- 모두 descriptor 7/thread 2를 유지했고 본인 서비스 프로세스 종료를 확인했다. 각 artifact ZIP/report
  SHA-256과 전체 113/114개 src Python 파일·시험 SHA를 해당 Git commit에 대조했다.
  [원본과 공개 출처](../evidence/review-endurance-2026-11-06/README.md)에 결과를 보존했다.
- 각 source에 들어간 수정 범위를 구분하며 겹친 실행 시간을 합산하지 않는다. 실제 PG/TLS/서명과
  합성 issuer·측정값의 차이, 운영 부하/전체 통제 인수 미검증 상태를 유지한다.
  연결 수 예산을 추가한 `68ec731`의 별도 30분 시험은 아직 진행 중이다.

### SVC-35 최종 이미지 근거 보존

- 최종 producer ec4aac6의 image artifact도 별도로 내려받아 GitHub ZIP digest를 대조했다.
  manifest의 wheel/requirements/Dockerfile·Git lock/준비 스크립트, decision의 scan/SBOM/runtime
  재고 해시와 image ID를 확인하고 [원본 폴더](../evidence/service-image-scan-2026-11-06/qualified-ec4aac6/README.md)에 보존했다.
- DB 갱신 시각은 12:55:02Z이며 관측은 15:25:23Z다. HIGH 49/고유 CVE 13, OS 87/Python 10,
  BLOCK이 유지됐다. 초기 d9 source의 이미지 증거를 최종 이미지로 대신하지 않는다.
