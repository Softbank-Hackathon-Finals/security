# ADR-0006: 현재 경로 묶음 조회와 고정 타입 정보 재사용

- 상태: 구현, 로컬 Python 3.14/실제 PostgreSQL 회귀 검증.
- 요구: SEC-PATCH-05·10, CTRL-02·07, POL-03·09·11.
- 기준: platform `c225c86cf5e408b5fcd016b0e367d3672d1bac44`.

## 근거

원격 `baba9ba` CI에서 서명 원본이 모두 있는 서비스 경로 15개가 실패했다. 후속 `5abc729`
CI에서는 같은 경로가 통과해 환경 부하에 따른 간헐적 실패 가능성이 남았다. 실패 로그만으로
원인을 단정하지 않는다. 추가 프로파일링에서는 한 요청이 같은 program 문서를 수백 번
해석하고 Python 타입 annotation을 수만 번 조사하는 비용을 확인했다.

기한을 늘리지 않고 반복 작업을 줄인다. 계측 자체도 실행 시간을 늘리므로 아래 수치는
프로파일러를 켠 비교이며 운영 응답 시간이나 SLA가 아니다.

## 결정

1. `modernization_codec`은 고정 코드의 dataclass 필드/타입 정보만 최대 128개 재사용한다.
   입력 문서, 검증된 객체, 등록, 서명, 키, 행, 철회 상태, PASS는 캐시하지 않는다.
   매 decode는 필드/타입 검사, 생성자 검증, 정규화 검사를 다시 수행한다.
2. `PostgresSecurityArtifacts.program_routes`는 최대 65행을 조회해 64개 한도를 강제한다.
   현재 tenant/application/environment/resource/program에 속한 최신 활성 이벤트와
   본문을 한 SQL 문장으로 읽는다. 각 digest·종류·revision·원본 binding을 검사하고
   공유 program을 조회 전후 다시 읽는다. 다른 호출의 결과를 사용하지 않는다.
3. `SignedProgramEvidence`의 선택형 경로 묶음 인증은 원본 수집 전후 전체 현재 경로와
   program을 다시 대조한다. `RegisteredProgramAuthority`는 이를 실제 저장소 조회에
   연결한다. 기존 개별 callback도 유지하며 두 방식에 동일한 변조/철회 시험을 적용한다.
4. 서명 원본과 현재 issuer 신뢰의 전후 검증, 현재 hold/등록/온라인 신원 확인, 5초 기한은
   유지한다. READ COMMITTED의 재조회는 분산 잠금이나 즉시 전역 철회를 뜻하지 않는다.

## 검증

- 동일 로컬 잠금 의존성/Python 3.14의 계측: 첫 요청 전체 함수 호출 약 3,598만 → 1,122만,
  프로파일러 기록 시간 9.618초 → 2.967초. 수정 전 계측 요청은 전송 기한을 넘겼고,
  수정 후에는 정상 결과 및 다음 issuer 철회 거부를 확인했다.
- 묶음 조회에서 route 철회 후 제외, 다른 resource 거부, 읽는 도중 부모 program 철회를
  별도 실제 PostgreSQL 시험으로 확인했다. 기존 등록 충돌·최신 원본 교체·동일 시각 모호성·
  tenant 격리 시험도 유지한다.
- 타입 정보가 준비된 뒤에도 알 수 없는 필드/종류/enum, 잘못된 scalar 및 시각은 거부한다.
- 실제 PG/OPA/Kubernetes API와 최신 플랫폼을 포함한 잠금 Python 3.14 전체 시험:
  **826 PASS, 123.68초**. 팀 배포의 RTT·부하·CNI·관측 원본은 별도 인수한다.
