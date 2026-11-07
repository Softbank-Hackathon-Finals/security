# 맥 T14·T33 인수 실행 준비

상태: **로컬 진단 구현, 실제 플랫폼 인수 미완료**. 기준 platform
`c364e6284d2e635ff86001e2feac88560ed23ebc`. 기존 [접속·조회 절차](platform-readonly-intake.md)와
[실환경 변경 시험 조건](platform-live-acceptance.md)을 재사용한다.

## 오프라인 준비와 제출 원문 요약

새 `sova security-intake-plan`은 설치된 security 0.11.1의 정본 T5 `full:1` 고정본에서
20개 시험의 ID·method·기대값·대조군 요구를 읽는다. 클라우드 SDK 호출·외부 명령·자원 변경은
없다. 입력이 없으면 양쪽 모두 20개 `NOT_PROVIDED`로 남는다. **종료 코드 0은 진단 생성
성공이며 인수 PASS가 아니다.** 부분 프로필로 축소하는 옵션은 없다.

```sh
# 준비한 맥의 개인 작업 폴더에서, 기존 안내에 따라 검증한 0.11.1 wheel과 Sova를 설치한다.
umask 077
sova security-intake-plan > intake-plan.json

# 기존 인증된 T14/T19 조회 경로로 얻은 ControlRun 원문과 T33 SourceStatus만 사용한다.
# 아래 파일은 예시 이름이다. Secret 값이나 원시 공급자 응답을 넣지 않는다.
chmod 600 source-control-run.json target-control-run.json aws-source-status.json
sova security-intake-plan \
  --control-run source-control-run.json --control-run target-control-run.json \
  --source-status aws-source-status.json > intake-with-reports.json
```

입력 파일은 기존 Mac/Linux 소유자 검사기를 통과해야 한다(본인 소유, 일반 파일,
그룹·다른 사용자 권한 없음, symlink 거부, 파일당 2 MiB 이하). Windows에서는 무입력 계획
생성만 지원하며 파일 소유권 검사를 우회하지 않는다. 출력에는 입력 파일 경로·환경/앱 식별자·
명령·발췌·URL·원문 오류 대신 스키마 고정 ID, 입력 hash와 보고된 상태만 넣는다.
공개 전에는 기존 공개 증빙 절차를 별도로 따른다.

`reported_counts`의 PASS는 **입력 문서가 주장한 값**이다. 서명·현재 등록·실제 계획 결속은
검증하지 않았으므로 모든 행의 `acceptance=LIVE_NOT_VERIFIED`, `authorizes_execution=false`를
유지한다. `3 PASS / 17 UNKNOWN`을 입력하면 그 개수를 보존하며, 만료 증거는 별도로
`EVIDENCE_NOT_CURRENT`다. 서로 다른 실행의 PASS를 합치거나 누락 행을 0건 정상으로 채우지 않는다.
최종 판정은 기존 T19가 인증된 원문·현재 계획으로 다시 수행한다.

## T14의 20개 준비 항목

아래 T번호는 기술 연결 위치다. 새로운 담당 배정이나 운영 변경 승인이 아니다.
정확한 방법·대조군·범위는 T5와 T14 안내를 따른다. 개인 PC에서 실제 운영 명령을 자동 실행하지 않는다.

| 시험 | 확인할 내용 | 준비 자격·환경 / 연결 |
|---|---|---|
| SEC-01.1 | 타 주체의 같은 Secret 읽기 거부 | T7/T9, 양쪽 정상·거부 신원과 현재 Secret 참조 |
| SEC-01.2 | 소스·렌더 설정의 평문 비밀 | T14, 승인된 소스 snapshot·고정 gitleaks·설정 |
| SEC-01.3 | 로그 비밀 노출 부재 | T14/T34, 시험 카나리·검색 scope·주입/복원 변경 창 |
| SEC-01.4 | 비밀 회전·기존 DB 연결 종료 뒤 재시작 없는 회복 | T7/T9/T14, 격리 시험 Secret·회전·쓰기 시험 창 |
| ENC-02.1 | Secret 저장 암호화 | T6/T9/T14, 현재 버전·키 메타데이터 읽기 |
| ENC-01.1 | 앱→Pooler 정상 인증 TLS | T6/T30/T14, 현재 앱·Pooler·CA·호스트명 |
| ENC-01.2 | 잘못된 CA/호스트명 거부 | 같은 경로, 앞뒤 정상 대조와 명확한 TLS 거부 |
| ENC-01.3 | 앱→Pooler 평문 거부 | 같은 경로, 비밀번호 없는 거부 탐침·정상 대조 |
| ENC-01.4 | 논리 복제 TLS | T8/T14, 등록 구독·슬롯·실제 sender 연결 읽기 |
| ENC-01.5 | Pooler→DB TLS | T6/T30/T14, Pooler 설정과 실제 DB 연결의 TLS 상태 |
| AUD-01.1 | DB 관리자 로그인 검색 | T34/T14, 시험 신원·원문 검색·허용된 카나리 창 |
| AUD-01.2 | DDL 검색 | T34/T14, 전용 schema·DDL 카나리·복원·검색 권한 |
| AUD-01.3 | K8s 권한 변경 검색 | T34/T14, 전용 RoleBinding·정리·감사 검색 권한 |
| NET-01.1 | 외부 공개 포트 범위 | T6/T30/T14, 등록 외부 위치·범위·스캔 창 |
| NET-01.2 | 외부→DB 5432·6432 접근 거부 | T6/T30/T14, 클러스터 밖 거부·안쪽 정상 대조 |
| NET-01.3 | 다른 앱·namespace 네트워크 경계 | T30/T14, 분리된 시험 신원·같은 시간창의 대조 |
| IAM-01.1 | 무인증 객체 읽기 거부 | T9/T14, 시험 객체·서명 읽기 정상 대조 |
| IAM-01.2 | 과도한 권한 부재 | T14, Prowler/kube-bench 결과·확정 점검 ID·현재 역할 |
| ISO-01.1 | 앱 간 객체·DB 격리 | T30/T14, 서로 다른 앱 둘과 각자의 정상 접근 |
| DR-01.1 | 실제 백업·복원·삭제 제한 | T35/T14, 백업 ID·격리 복원 namespace·표식·삭제 거부 |

이번 양쪽 TLS 증빙에서 통과한 세 시험은 ENC-01.1/.2/.3뿐이다. Pooler→DB와 복제 TLS,
OpenBao 자격 이전, 감사·복원까지 통과한 것으로 확대하지 않는다. 업무 쓰기/회전/카나리/
복원·삭제 거부 시험은 현재 공용 환경 읽기 전용 범위에 포함되지 않으며 기존 담당 변경 창으로 넘긴다.

## T33의 실제 수집 인수

| 경로 | 준비·실행 순서 | 필요한 실제 근거 |
|---|---|---|
| AWS | `bravo-personal` SSO 계정 대조 → 등록된 Security Hub 또는 명시적 GuardDuty 경로 → 기존 수집기 | 정상 조회·샘플/양성 탐지·scope와 cursor, 실패 후 기존 결과 보존 |
| GCP | 실제 프로젝트·SCC 활성 범위·조회 전용 인증 확인 → 기존 `SccSource` | 실제 필터·페이지·정규화·인증 API 조회, 권한 거부·중단 구분 |
| 온프렘 | 기존 Kyverno/Falco와 에이전트·바깥 방향 수신 경로 확인 | 실제 PolicyReport/이벤트·등록 환경 신원·수신·중단/STALE·정리 |

현재 status가 OK라도 양성 탐지 수집이나 앱의 안전을 증명하지 않는다. FAILED에 과거의
성공 시각이 붙어도 정상으로 복구하지 않는다. INGESTION_GAP, 권한 거부, 미활성, 타임아웃은
구분해 보존한다. `source_status` 파일은 이 상태 정리용이며 실제 Finding·cursor·정규화기
실행의 원본 수집 근거를 대체하지 않는다.

마스킹된 AWS 계정/자원을 개인 앱 등록에 복사해 매핑을 맞추지 않는다. 원본 UID·revision과
정규화 결과를 묶는 인증된 수집 매핑은 후속이다. 기존 [탐지 연결 계약](detection-integration.md)을 따른다.

## 맥 완료 기록

실제 runtime imageID·source/config hash, plan/run/application, 양쪽 UID·revision,
관측 시작/종료·원문 hash·독립 신뢰 anchor와 T19의 판정을 기존 인계 기록에 남긴다.
로컬 진단, 실제 수집, T19 실환경 소비, 운영 변경 시험·복구 인수를 각각 구분한다.
끝나면 이번 작업이 연 포워드만 종료하고 보존 증거와 기존 세션은 유지한다.
