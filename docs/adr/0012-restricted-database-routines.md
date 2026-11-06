# ADR-0012: 관리 함수 EXECUTE도 읽기 전용 역할의 권한 경계다

- 상태: 실제 PG17 재현·수정 검증, PG18 CI 확인 예정.
- 요구: SG-1, CTRL-01·02·04, POL-01, SEC-PATCH-10. 플랫폼 기준 `9e0d6a5`.

## 재현

SELECT-only 테이블 권한과 FORCE RLS가 유지되어도 관리자가
`pg_catalog.pg_read_file(text)` 실행을 추가 허용하면 서버 파일을 읽을 수 있다.
이 함수는 `SECURITY DEFINER`가 아니며 기존 사용자 스키마의 untrusted 함수 검사에도 걸리지 않았다.
별도 disposable DB에서 역할 직접 grant와 PUBLIC grant 두 경로를 재현했다.
읽은 파일은 해당 시험 클러스터의 공개 `PG_VERSION`뿐이다. 기존 guard를 유지한 회귀 시험은
**2 FAIL, 0.27초**였고 파일 읽기가 성공한 뒤에도 guard가 거부하지 않았다.

## 결정

기존 함수 권한 조회에 `pg_init_privs`의 초기 ACL을 결합한다. initdb/extension 설치 때
PUBLIC EXECUTE가 없었던 함수인데 현재 reader가 schema USAGE와 EXECUTE를 가진 경우 거부한다.
고정 위험 함수 이름 목록에 의존하지 않아 PG17/18에서 초기 제한된 관리 함수를 함께 확인한다.
기존 definer·사용자 untrusted 함수 검사, 역할 membership 금지, 테이블/RLS 검사는 유지한다.
DB의 실행 권한을 서비스가 임의로 수정하지 않는다.

별도 관리자 REVOKE 뒤 직접 함수 실행은 PostgreSQL `InsufficientPrivilege`로 거부되고
서비스 guard는 정상으로 복구됨을 확인한다. 현재 DB 경계/독립 TLS 서비스 묶음은
**49 PASS, 16.91초**다. 같은 시험을 PG18.4 이미지 CI에도 추가했다.

이 guard는 잘못된 배포를 거부하는 장치다. 이미 탈취된 과다 권한 DB 계정의 권한을 실제로
회수하는 작업은 별도 관리자의 책임이다. 초기 ACL catalog를 변조할 수 있는 악성 DBA나
OS 관리자까지 방어한다고 주장하지 않는다. 공유 DB의 PUBLIC 변경은 영향 범위를 검토해야 한다.

참조: [초기 권한 catalog](https://www.postgresql.org/docs/17/catalog-pg-init-privs.html),
[서버 관리·파일 접근 함수](https://www.postgresql.org/docs/17/functions-admin.html).
