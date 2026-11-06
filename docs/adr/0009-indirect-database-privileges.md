# ADR-0009: 테이블 밖의 서비스 DB 권한도 검증

- 상태: 구현, 실제 PostgreSQL 17 회귀 검증. PostgreSQL 18.4 CI 검증 대기.
- 요구: SG-1, CTRL-01·02·04, POL-01, SEC-PATCH-10.
- 플랫폼 기준: `9e0d6a59d7a00925ddafc50cfa2ccad00c5ba768`.

## 재현한 문제

테이블 다섯 개의 SELECT와 고정 restrictive RLS만 검사하면 간접 접근 권한을 놓친다.
격리된 PostgreSQL에서 별도 관리자가 만든 SECURITY DEFINER 함수 또는 소유자 권한의 뷰를
PUBLIC에 열었을 때, 서비스 역할의 직접 테이블 조회는 0행이었지만 그 경로는 다른 tenant의
합성 hold ID를 반환했다. 변경 전 guard는 두 경우 모두 거부하지 못했다(새 회귀 시험 2 FAIL).
실제 운영 데이터를 읽거나 플랫폼 DB에 객체를 만든 시험은 아니다.

이는 PostgreSQL의 기본 권한 모델과 일치한다. 함수는 생성 시 PUBLIC EXECUTE를 기본으로
가지며, 일반 뷰는 기본적으로 소유자 권한으로 기반 관계에 접근한다.
[함수 권한](https://www.postgresql.org/docs/17/sql-createfunction.html),
[뷰/규칙 권한](https://www.postgresql.org/docs/17/rules-privileges.html).

## 결정

`require_reader`는 요청 전후 다음 상태도 거부한다.

- replication·DB CREATE 또는 비시스템 schema CREATE 권한.
- 필요한 다섯 테이블의 열 단위 INSERT/UPDATE/REFERENCES 권한.
- 접근 가능한 SECURITY DEFINER 함수/프로시저, 사용자 schema의 untrusted-language 함수.
- 다섯 테이블 밖의 일반/partition/foreign table, view/materialized view에 대한 테이블·열 권한.
- 사용자 sequence 권한, large object 소유권·자신/PUBLIC의 SELECT/UPDATE 및 legacy 호환 모드.

기존 invoker SQL·trigger 함수의 의미는 유지한다. PostgreSQL 17에는 여기서 필요한
`has_largeobject_privilege`가 없어 첫 구현 시험이 실패했다. 소유권과 실제 `lomacl`을 검사하는
형태로 수정했으며, membership 없는 전용 역할이라는 선행 조건을 유지한다.
서비스 연결의 search_path도 pg_catalog로 고정한다. 기존 schema와 wire 계약은 변경하지 않는다.

PUBLIC 권한은 개별 역할의 REVOKE로 상쇄되지 않는다. 따라서 서비스는 자동으로 다른 객체의
권한을 바꾸지 않고 잘못된 배포를 거부한다. 관리자는 자기 전용 보안 DB의 기본 PUBLIC 권한을
회수하고 필요한 registrar에만 허용한 뒤 다시 인수한다. 업무 DB와 공유하기 위해 guard를
끄거나 임의 객체를 허용 목록에 넣는 방식을 기본값으로 사용하지 않는다.

## 검증과 남는 경계

수정 후 `test_review_database_escape.py`, 기존 PostgreSQL 경계, 독립 TLS runtime 묶음은
**47 PASS, 19.73초**였다. 재현한 두 경로는 guard가 거부했고, 별도 관리자가 PUBLIC 권한을
회수한 뒤에는 직접 SQL도 InsufficientPrivilege가 됐으며 guard가 다시 통과했다.
열 권한·replication·schema/DB CREATE·추가 테이블 열·sequence·large object drift도 검사했다.

기존 전체 package CI는 PostgreSQL 17을 유지한다. 서비스 이미지 CI는 공식 digest가 확인된
PostgreSQL 18.4에서 DB 경계 및 실제 컨테이너/T10 경로를 시험하도록 추가했다. 팀 CNPG의
extension·기본 권한·인증·TLS 경로는 별도 인수 대상이다.

guard의 거부 자체가 이미 과도한 권한을 가진 **탈취 DB 자격**을 무력화하지는 않는다.
직접 접근을 막는 것은 관리자의 실제 grant 회수·자격 철회·DB/네트워크 격리다. DBA/superuser,
악성 DB extension·OS 관리자, 모든 SQL 기능의 완전한 격리를 증명한다고 주장하지 않는다.
