# ADR-0017: DB 전체 역할과 데이터베이스별 접속 경계

- 상태: 구현·개인 PostgreSQL 17.11 및 CI PostgreSQL 18.4 실측, CNPG 운영 인수 전.
- 요구: SG-1·2, CTRL-01·06, SEC-PATCH-08, identity-boundary.
- 플랫폼 기준: `8b12236ae4277de16cebdf1391f87721e5851d47`.

## 발견과 결정

현재 고정 테넌트 RLS와 `require_reader`는 연결된 DB의 객체·권한을 검사한다. PostgreSQL 로그인 역할은
클러스터 전체에 존재하고 기본 PUBLIC CONNECT는 다른 DB에도 있을 수 있다. 탈취한 비밀번호로
서비스의 고정 DSN을 벗어나 같은 서버의 다른 DB에 접속하면 그 DB의 PUBLIC 객체가 노출될 수 있다.
NetworkPolicy가 같은 DB 서버 IP/port만 허용해도 이 경로를 구분하지 못한다.

새 `reader_hba_rules`는 기존 SELECT/RLS를 유지하면서 **직접 TCP 연결용** 운영 설정을 렌더링한다.
정확한 DB·별도 reader 역할·등록된 CIDR·TLS/SCRAM만 허용하고, 이후 그 역할의 다른 DB·평문·다른 주소·
physical replication·Unix socket 연결을 거부한다. 관리자/복제/pooler 계정은 입력으로 거부한다.
규칙은 문자열 자료만 반환하며 DB나 Kubernetes에 적용하지 않는다. 서비스 프로세스에 HBA 쓰기 권한을 주지 않는다.

```python
from sova_security.adapters.review_database_network import reader_hba_rules

rules = reader_hba_rules(
    role="security_reader", database="platform",
    client_networks=["10.42.0.0/16"],  # 실제 CNI/NAT에서 확인한 허용 출발지로 등록
)
```

이 CIDR은 사용 예시이며 운영 허용 범위가 아니다. Kubernetes namespace+app NetworkPolicy와 함께
최소 범위로 등록한다. DB 이름이 `all`이어도 따옴표로 literal 처리하며 hostname, 정규식, 역할 그룹,
개행, 전 주소 허용과 모호한 CIDR 입력을 거부한다.

## CNPG와의 호환

CNPG의 `.spec.postgresql.pg_hba`에 기존 더 넓은 사용자 규칙보다 **앞에** 넣는 후보이다.
CNPG는 고정 규칙, 사용자 규칙, 선택 LDAP, 기본 규칙 순서로 생성한다. 첫 일치가 적용되므로
이미 앞에 허용 규칙이 있으면 뒤의 reject는 보호하지 못한다. 실제 생성 파일과 긍정/거부 대조군을 인수한다.
공유 Cluster의 다른 규칙 전체를 교체하거나 PUBLIC CONNECT를 일괄 REVOKE하지 않는다.

CNPG의 고정 local peer 규칙과 내부 복제/pooler 규칙은 이 목록보다 앞이다. 따라서 이 렌더러는
CNPG 내부 계정이나 로컬 OS 침해를 격리했다는 근거가 아니다. reader의 DB socket mount/Pod exec와
OS 계정 접근을 별도로 제한한다. 서비스가 private Unix socket으로 연결되는 기존 로컬 시험 프로필에는
이 TCP 전용 설정을 자동 적용하지 않는다.

Pooler를 경유하면 DB가 보는 사용자/출발지가 바뀔 수 있다. CNPG의 고정 pooler 인증을 이 역할과
동일하다고 가정하지 않는다. 직접 DB 경로를 먼저 검증하고 pooler를 쓸 때는 실제 사용자 매핑,
pooler 데이터베이스 allowlist와 양쪽 TLS/인가 거부를 별도로 시험한다.

CNPG 1.30 문서의 pod selector 동적 주소 기능은 같은 namespace만 지원한다. 보안 서비스와 DB의
namespace 분리를 그대로 유지하며 지금 그 기능이나 placeholder를 자동 활성화하지 않는다.
Pod IP/NAT 변경 시 기존 운영 등록 갱신·재검증을 따른다.

## 시험과 남는 조건

- 단위 시험 30개: literal 결속, IPv4/IPv6 deny, 잘못된 역할/DB/주소와 규칙 삽입 거부.
- 로컬 단위와 실제 PostgreSQL 17.11/TLS를 합해 **31 PASS, 0.55초**였다.
- 실제 시험은 `sova-security-test`/`sova_security_test`와 private 관리자 socket을 먼저 확인한다.
  임의 이름의 다른 DB에 합성 공개 canary를 만들어 기존 credential의 접근을 재현한다.
  HBA를 적용해 허용 DB의 verify-full TLS는 유지하고 다른 DB·평문·미등록 주소를 거부한다.
- 변경 전 HBA bytes를 보존하고 `finally`에서 정확히 복원·reload한다. 별도 reader와 DB만 제거한다.
  운영 DB나 플랫폼 Cluster를 수정하지 않는다. CI는 별도 PostgreSQL 18.4 컨테이너에서 시험한다.
- HBA reload는 이미 열린 세션을 끊지 않는다. 시험도 이전 연결이 살아 있음을 확인한다.
  침해 시 기존 host hold/승인 차단 후 자격 철회와 **식별된 역할의 기존 세션 종료**를 별도 운영 경로에서 수행한다.
  reader 자체에 다른 backend 종료 권한을 부여하지 않는다.
- 서비스의 `require_reader` 성공을 이 접속 경계의 설치 증거로 해석하지 않는다. 운영 입증이 없으면
  관련 identity-boundary 근거는 UNKNOWN이다. DB 관리자 침해, connection quota, 복원 뒤 철회 원장 회귀는 별도 조건이다.

근거: [PostgreSQL 18 HBA 규칙](https://www.postgresql.org/docs/18/auth-pg-hba-conf.html),
[CNPG 1.30 설정 원문](https://github.com/cloudnative-pg/cloudnative-pg/blob/release-1.30/docs/src/postgresql_conf.md).
