# ADR-0003: 요청 단위 연결과 현재 증거 묶음 검증

- 날짜: 2026-11-06
- 상태: 구현, 로컬 PostgreSQL/TLS 검증. 운영 클러스터 성능 인수 전.
- 요구사항: SEC-PATCH-05·10, CTRL-02·07, POL-03·09·11.
- 플랫폼 기준: `b19488e2debbee8bbe120f1309eadbe19df85b6f`; wire 계약 변경 없음.

## 발견과 결정

서비스 시험에 모든 검사에 대한 서명 원본을 추가하자 5초 요청 기한을 초과했다.
UNKNOWN 결과만 시험해서는 이 문제를 발견하지 못했다. 제한을 늘리거나 철회 검증을
생략하지 않고, 요청 안에서 PostgreSQL 연결을 재사용하고 현재 증거 묶음을 검증한다.

`RequestScopedReader`는 ContextVar로 요청을 분리한다. 처음 필요한 시점에 연결하고
고정 tenant/SELECT 권한을 확인한다. 각 기존 저장소 호출은 READ COMMITTED의 새
트랜잭션으로 읽는다. 요청 종료 시 역할·정책을 다시 확인하고 연결을 닫는다.
예외 때도 닫고, 종료 검증으로 응답 기한을 넘기면 성공 결과를 반환하지 않는다.
연결만 공유하며 행, 역할, 토큰, PASS를 캐시하지 않는다.

`SignedProgramEvidence.authenticate_batch`는 같은 `_collect`로 현재 program, route,
원본 envelope, issuer trust를 다시 조회하고 서명을 검증한다. 검증 전후 원본 비교와
철회 검사는 유지한다. 요청한 정확한 program/phase/증거 tuple과 현재 결과가 같아야
한다. 기존 개별 검증 인터페이스도 유지하며 선택적 묶음 callback은 호스트가 제공한다.

## 실패와 검증

연결 재사용만으로는 전체 증거 경로가 기한을 만족하지 못했다. 묶음 callback이 검증된
tuple을 반환한 첫 구현은 공통 인증 계약이 거부했다. 공통 계약은 True/None 또는
정확한 dataclass만 허용한다. 계약을 완화하지 않고 검증 완료 후 True를 반환하도록
수정했으며 실제 서비스를 통해 다시 확인했다.

- `pytest tests/unit/test_security_program.py tests/unit/test_program_evidence.py
  tests/unit/test_review_connections.py -q`: 56 PASS.
- 격리 PostgreSQL 17.11 + 실제 TLS + 온라인 Ed25519 토큰 검증 **모형**:
  `pytest tests/integration/test_review_host_runtime.py -q`: 7 PASS, 10.44초.
  전체 서명 증거의 정상 응답과 issuer 신뢰 철회 후 거부를 포함한다.
- 연결 교차 오염, 예외 시 닫기, 종료 시 정책 검사, 종료 중 만료,
  증거 누락·변조·철회·조회 중 변경을 검증했다. Ruff 통과.

이 결과는 로컬 격리 환경의 기능 검증이다. 운영 DB의 RTT·부하·CNI·실제 TokenReview
응답 시간은 별도 인수한다. 5초 기한을 맞추지 못하면 변경 판정을 보류하며 과거 PASS로
대체하지 않는다. 기존 앱 서비스의 가용성과 보안 변경 승인 경로는 분리한다.
