# 통합 및 소유권

## 호출 경계

플랫폼이 인증한 tenant/application 범위, 검증된 대상 등록, 현재 revision과 독립 검사 근거를 제공한다. 패키지는 통제 판정·보류·검증 의무를 반환한다. 플랫폼은 사람 승인, 작업 임대, 실행 자격증명과 효과 원장을 소유한다. 패키지 allow는 실행 권한이 아니다.

코드·정책 변경은 먼저 Sova에서 검토·통합 시험하고 명시적인 패키지 반영 단위로 관리한다. 추출된 구현의 정본은 이 저장소다. Sova의 기존 import는 설치한 패키지로 연결하며 별도 구현 사본을 유지하지 않는다.

## 계약 v1

현재 공개 경계는 `contracts.commands`, `evidence`, `plans`, `graph`, `repositories`다. Sova는 동일 클래스·예외를 재노출해 중복 타입과 isinstance 오류를 방지한다. 이는 팀 전체 계약이 이미 합의됐다는 선언이 아니다. 호환되지 않는 팀 계약은 변환·계약 시험 후 연결한다. 공개 타입·문서 해시·직렬화 형태 변경은 호환성 검토와 버전 변경 대상이다.

## PostgreSQL

호스트의 마이그레이션 관리자가 `sova_control` 스키마를 만든 뒤 `sova_security.migrations.MIGRATIONS` 순서로 SQL을 읽어 적용한다. 패키지는 설치·import·저장소 생성 시 DDL을 실행하지 않는다. migration_sql은 정해진 리소스 이름만 허용한다.

패키지가 소유하는 것은 보안 보류·관측·서명 근거·검증기 신뢰·보호 정책/평가 테이블이다. 공통 operations 상태 제약과 security_routes, operations를 참조하는 atomic completion 테이블은 호스트가 관리한다. SQL 2개를 패키지로 옮겨 플랫폼 전역 상태 모델을 암묵적으로 변경하지 않는다.

실행용 DB 역할은 schema/table owner·superuser·BYPASSRLS를 허용하지 않는다. 인증된 tenant_id를 transaction-local로 설정하고 RLS를 적용한다. 공유 DB 자격증명 자체가 탈취된 경우 tenant 설정만으로 공격자 격리를 보장하지 않는다. 관리자 마이그레이션 역할과 런타임 역할은 분리한다.

기존 환경에는 스키마·데이터 변경이 필요하지 않다. SQL 내용·테이블명·document digest는 추출 시 유지된다. 스키마를 임의로 다시 적용하거나 실행 중인 DB를 초기화하지 않는다.

## 실행 경계

SecurityResponseGuard와 계획 모델은 포함하지만 실제 실행 runner는 호스트 코드다. 호스트의 기존 lease·승인·효과 CAS·불확실 결과 조회 복구를 사용한다. 보안 패키지에 별도 실행 원장을 만들지 않는다. 시험용 k3s executor와 프로세스 격리 도구도 포함하지 않는다.

## 시험 수준

패키지 독립 unit/contract 시험, 패키지 단독 PostgreSQL 접근 제한 시험, Sova 전체 회귀를 각각 기록한다. CI의 일반 단위시험에서는 실제 PostgreSQL 시험이 명시적으로 건너뛰어질 수 있다. 별도 격리 클러스터를 연결한 시험 없이 운영 자격을 주장하지 않는다. AWS unit 시험은 SDK Stubber를 사용한다.
# 인증 callback 반환 계약

권한 검사는 `True` 또는 거부 시 예외를 발생시키는 `None` 반환 방식을 지원한다. `False`·정수·문자열·임의 truthy 객체는 거부한다. 정책·근거 인증 callback은 이에 더해 입력과 정확히 같은 타입·내용의 검증된 dataclass를 반환할 수 있다. 서명 verifier가 인증한 `EvidenceRecord`를 반환하는 기존 연결은 유지한다. 반환값을 지정하지 않은 테스트 Mock도 승인이 아니므로 `return_value=None`을 명시해야 한다.

이 규칙은 HTTP 입력의 승인 표시가 아니라 신뢰된 호스트 callback의 계약이다. host가 잘못된 무조건 승인 함수를 주입하는 것을 패키지 자체가 방지하는 인증 서비스는 아니다.
