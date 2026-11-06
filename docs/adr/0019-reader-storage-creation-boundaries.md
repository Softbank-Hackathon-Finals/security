# ADR-0019: 전용 보안 DB의 임시 테이블·대형 객체 생성 제한

- 상태: 구현·단위 검증, 실제 사설 DB 재현/수정 CI 확인 중.
- 요구: CTRL-01·02·07, SEC-PATCH-08, identity-boundary, resource-budget.
- 플랫폼 기준: `98885a69999398bfe3f49fbc8324a7b19aae3e16`.

## 경계

테이블 SELECT/RLS 권한만으로 PostgreSQL 로그인 전체가 읽기 전용이 되는 것은 아니다.
PUBLIC의 기본 TEMPORARY 권한은 임시 테이블을 허용하고, `lo_create`, `lo_creat`, `lo_from_bytea`는
테이블 INSERT 없이도 대형 객체를 만든다. 탈취한 로그인은 앱이 넣는 read-only 접속 옵션을 생략할 수 있다.
대형 객체의 기존 소유/읽기 권한을 검사하는 것과 새 객체 생성 권한을 제한하는 것은 다른 조건이다.

## 결정

운영자 전용 `reader_database_statements(database=...)`는 전용 보안 DB의 PUBLIC TEMPORARY 및
위 세 생성 함수의 PUBLIC EXECUTE를 회수하는 SQL만 반환한다. 연결·실행은 하지 않는다.
시스템 DB·모호한 이름은 거부한다. 실제 공유 플랫폼 DB에 자동 적용하지 않는다.

PUBLIC 권한은 해당 reader에게 REVOKE해도 상쇄되지 않는다. 따라서 전용 보안 DB를 우선하고,
기존 다른 사용자가 필요한 권한은 소유자가 각각 검토·명시적으로 부여해야 한다. 서비스에 관리자
권한을 부여하거나 기존 사용자 권한을 자동 교체하지 않는다.

`require_reader`는 시작/종료 시 현재 역할의 TEMPORARY와 생성 함수 EXECUTE를 함께 검사한다.
직접 grant 또는 PUBLIC grant가 다시 생기면 신규 판정을 보류한다. 원래 다섯 테이블의 SELECT,
테넌트 고정 FORCE RLS, 현재 증거·철회 읽기는 유지한다. 프로토콜·승인·실행 책임은 바뀌지 않는다.

기존 `reader_statements`는 역할·테이블 정책 준비를 담당한다. 배포 순서는 전용 DB 준비 →
reader 생성 → 기존 T9 자격 공급 → 허용 읽기/쓰기 거부 확인이다. 이 변경 전 구성의 DB가 기본
PUBLIC 생성 권한을 유지하면 새 서비스 검사가 거부한다. 환경 인수 때 명시적으로 반영해야 한다.

## 시험과 제한

기존 사설 DB fixture는 정확한 cluster_name/DB 이름을 먼저 확인한다. PUBLIC 권한을 보존한 뒤
준비 SQL을 적용하고 종료 시 원래 부여 여부를 복구한다. 신규 시험은 TEMP와 각 생성 함수의 실제 거부,
직접/PUBLIC 재부여 때 drift 거부를 확인한다. 재현은 0~1 byte 객체 하나뿐이며 부하 공격을 수행하지 않는다.

REVOKE는 기존 객체를 제거하거나 세션을 종료하지 않는다. 침해 대응은 host hold와 별도 세션/자격 철회를
유지한다. CPU가 큰 SELECT, 서버 연결 수, spill/WAL/DB 전체 용량은 별도 운영 자원 통제와 경보가 필요하다.
이 제한을 DB 가용성 전체나 관리자 침해 방어로 확대하지 않는다.

근거: [PostgreSQL 18 권한과 PUBLIC/TEMPORARY](https://www.postgresql.org/docs/18/ddl-priv.html),
[대형 객체 서버 함수](https://www.postgresql.org/docs/18/lo-funcs.html).
