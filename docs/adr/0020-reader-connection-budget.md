# ADR-0020: 전용 reader의 DB 연결 수 상한

- 상태: 구현·실제 PG17.11/18.4 및 서비스 전체 CI 검증 완료. 운영 역할 인수는 별도.
- 요구: CTRL-07 자원 한도, CTRL-01 침해 범위 제한, SEC-PATCH-08 보호 보존.
- 플랫폼 기준: `98885a69999398bfe3f49fbc8324a7b19aae3e16`.

ASGI worker/HTTP 연결 한도는 탈취된 DB 자격의 직접 연결에는 적용되지 않는다.
PostgreSQL 역할 기본값 `CONNECTION LIMIT -1`은 무제한이다. 전용 reader를 만드는
운영자 SQL에 기본 16개를 지정하고 명시적 `connection_limit`은 정수 1~64만 허용한다.
이는 현재 서비스 기본 worker 16 및 선택형 ASGI 최대 64와 맞춘 검증 범위다.

`require_reader`는 기존 세션에서도 0/무제한/64 초과 변경을 거부한다. 기존 운영 역할을
자동 ALTER하지 않는다. 운영자는 배포 전에 역할별 실제 상한과 모든 소비 프로세스 수를
검토해야 한다. 역할의 상한은 같은 클러스터 전체 로그인에 적용되므로 여러 replica를
공유 역할로 배치하면 예산도 공유한다. 현재 명세의 단일 replica/Recreate를 유지한다.

검증은 본인 격리 DB에 상한 2인 reader를 만들고 정상 두 연결 → 세 번째 직접 연결 거부 →
다른 로그인 허용 → 본인 연결 종료 → reader 재접속 허용을 확인한다. 별도 기존 연결에서
상한을 -1/0/65로 바꿨을 때 runtime 거부도 확인한다. 작은 순차 시험이며 부하 공격이 아니다.

이 기능은 모든 DB 가용성을 보증하지 않는다. PostgreSQL은 상한을 근사적으로 집행하며
동시 접수 경합에서 둘 다 거부될 수 있다. superuser에는 적용되지 않고 일반 연결 외의
prepared transaction/background worker도 이 계산과 다르다. 기존 연결을 종료하지 않는다.
서비스 거부는 신규 위험 변경의 보류로 처리하며 무한 재시도나 앱 경로 의존을 추가하지 않는다.
CPU/쿼리 비용·전체 max_connections·공유 DB/다른 역할·네트워크 예산과 경보는 운영 인수 항목이다.

근거: [PostgreSQL 18 CREATE ROLE — CONNECTION LIMIT와 Notes](https://www.postgresql.org/docs/18/sql-createrole.html).

`68ec731` [CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42240519877)의
Python 3.14는 1,021 PASS/2 SKIP, PG18.4 권한은 58 PASS, HBA 1 PASS, image/T10 11 PASS다.
같은 source의 별도 지속 시험 완료 여부는 [원본 기록](../evidence/review-endurance-2026-11-06/README.md)에 따른다.
