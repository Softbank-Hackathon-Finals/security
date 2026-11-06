# ADR-0002: 서비스 DB 자격을 한 테넌트로 제한

- 상태: 채택 — PostgreSQL 실측 완료, 클라우드 배포 인수는 별도.
- 기준: platform `f602b39a949b99f3e2e7be901103063e78a52a70`
- 요구사항: SG-1, CTRL-01·02·04, POL-01, SEC-PATCH-10

기존 `ScopedPostgresSession`의 RLS는 인증된 호출 경로의 tenant 혼선을 방지한다.
하지만 DB 자격을 탈취한 공격자는 `sova.tenant_id`를 직접 바꿀 수 있다. 읽기 전용
역할만으로 이 위협을 해결했다고 주장할 수 없으므로 서비스 배포를 테넌트별로 분리한다.

서비스 전용 역할에는 필요한 다섯 테이블의 SELECT만 준다. 기존 permissive tenant
정책에 역할별 restrictive 정책을 추가하여 **세션 값과 고정 tenant가 모두 일치**해야
행을 읽을 수 있게 한다. 새 schema나 일반 저장소의 의미를 바꾸지 않는다. 정책은 별도
관리자가 적용하며 서비스 자체는 생성·수정 권한이 없다. 일반 registrar 역할에는 영향을 주지 않는다.

서비스는 매 연결에서 고정 정책, FORCE RLS, 테이블 소유권, SELECT 이외 권한,
역할 membership, superuser/BYPASSRLS/CREATEROLE/CREATEDB 및 schema CREATE를 검사한다.
정책 제거·다른 tenant 지정·쓰기 권한 추가·역할 상속은 서비스 판정을 중단시킨다.
임의 DB owner, superuser, 노드 관리자 침해까지 방어하는 경계는 아니다.

`reader_statements`는 비밀 없는 DDL 객체만 만든다. 로그인 자격은 기존 OpenBao/CNPG
관리 경로로 발급·회전한다. 같은 역할 이름을 재사용하거나 기존 역할을 자동 고치지 않는다.
단일 tenant 안의 여러 앱은 여전히 하나의 DB 읽기 경계를 공유하므로 더 강한 격리가
필요하면 앱별 역할/DB로 나누고 정책을 확장·검증해야 한다.

검증: 실제 PostgreSQL에서 직접 GUC를 다른 tenant로 변경해도 행 0개, 정상 tenant
읽기 성공, 네 종류의 권한/정책 drift 차단. 로컬 TLS·서명 토큰 검증기 모형과 이 역할을
함께 사용한 API 시험은 클라우드 IAM/RBAC 실측을 대신하지 않는다.

후속 [ADR-0009](0009-indirect-database-privileges.md)는 PUBLIC 함수·뷰의 간접 접근을 실제
재현하고 열 단위 권한·replication·추가 객체 권한까지 검사를 확장했다. 테이블의 고정 RLS만으로
모든 DB 경로를 제한했다고 해석하지 않는다. 전용 보안 DB의 실제 PUBLIC 권한 정리가 필요하다.
