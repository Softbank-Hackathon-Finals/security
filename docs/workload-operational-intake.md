# 워크로드 보안 시각화: 운영 연결 인계

2026-11-07 KST. 현재는 표시 코드·로컬 계약 검증 단계다. 아래 변경은 실행하지 않았다.
플랫폼 배포, 서비스 권한 발급과 실제 격리·복구 시험은 기존 담당의 운영 경로에서 진행한다.

## 연결 순서와 담당 경계

| 순서 | 기존 경로 / 구체적인 연결 | 필요한 작업 | 확인할 결과 |
|---|---|---|---|
| 1 | T7/T10 `platform-state`의 호스트·등록 API·Reader | 승인된 이미지와 해당 Reader 설정을 기존 GitOps 배포에서 함께 준비 | 실제 imageID·설정 revision·Ready 일치. Ready만으로 이후 인수 통과 아님 |
| 2 | T7/T9의 서비스 신원·비밀 관리 | 전용 보안 생산자 SA UID, 단일 audience·짧은 수명의 projected token, TLS 신뢰/접속 참조 등록 | 유효 요청과 만료·다른 audience·교체 UID·철회 요청을 구분. Secret 값은 인계하지 않음 |
| 3 | 기존 T10 계획 저장·열람 권한 | 실제 plan ID/digest/version·앱·양쪽 환경과 읽기 전용 스냅샷 저장소를 연결 | 정상 계획만 열람. 다른 테넌트·미등록 앱·계획 변경은 거부 |
| 4 | security `project_security_snapshots` → 콘솔 `PlanWorkload` | 검증된 생산자 SHA·생산자 ID·원문 해시와 인증 callback 등록. 같은 T10 API를 사용하는 기존 콘솔에 조립 | 구성 경고만 표시. 위조 출처·변조 본문·철회·만료·과거 revision은 현재 성공으로 표시하지 않음 |
| 5 | 기존 T10 승인/잠금·T31/T12 실행·효과 원장 | 계획·자원 UID·승인·효과와 독립 readback을 결속한 공급자 연결 | 요청만 있을 때 격리 미완료. 해당 자원의 거부 탐침 후에만 확인 표시 |
| 6 | T24 감사·T35 복구·기존 recovery authority | 같은 기록 ID로 보존/조회, 별도 복구 승인·원본 대조 | 화면 이력과 저장 원본 일치. 복구 성공과 사고 보류 해제를 별도로 확인 |

새 승인기, 게이트 또는 범용 실행기를 만들지 않는다. 표시 계약의 `authorizes_execution=false`를
유지한다. UI의 구성 요소 선택·합성 시나리오는 실제 실행기 호출 경로가 아니다.

## 읽기 전용으로 확인할 수 있는 범위

계정·클러스터 UID·SSM 대상, Pod imageID/Ready, ServiceAccount UID, RBAC 선언,
NetworkPolicy·Service/EndpointSlice, ConfigMap 참조·revision은 조회할 수 있다.
현재 Mac은 `bravo-personal`과 기존 플랫폼 SSM 포워딩만 사용한다. 목적지 접속 ZIP은 이 경로가 아니다.

RBAC나 NetworkPolicy가 존재하는 것만으로 실제 권한·통신 거부를 PASS로 만들지 않는다.
읽기 전용 점검에서는 서비스 token 발급, Pod exec, 권한 철회, 연결 차단, 복구·컷오버를 하지 않는다.
유효한 대조 요청과 실제 거부 시험은 별도 인수 창이 필요하다.

## 실행 전에 고정할 인계 항목

비밀값 대신 다음 참조와 책임만 맞춘다.

- 배포/시험 시간과 충돌하는 작업, 시험 중 중지·복구를 담당할 주체.
- 실제 계획·앱·출발/목적지의 등록 참조와 revision.
- 배포 승인된 이미지의 distribution digest, 코드 SHA, 설정 revision.
- 보안 생산자 신원·현재 SA UID·audience·TLS 신뢰 참조·읽기 저장소 참조.
- 운영 열람 권한과 별도의 변경 승인 범위, 등록/철회 writer의 T10 계획 잠금 사용 여부.
- 격리·대체·복구 영수증의 생산자와 검증 방법, 감사 기록 저장 위치/보관 정책 참조.

상태 변경 시험의 사전 조건이 충족되지 않으면 해당 항목은 미검증으로 유지한다. 합성 결과로
대체하거나, 권한을 넓혀 진행하거나, 기존 운영 자료를 삭제 시험 대상으로 사용하지 않는다.

## 최신 코드와 기존 자격의 차이

인계 플랫폼 기준은 `0795f65e24f58e43545b16b97757efcc0923fd4a`다. 후속으로 병합된
`6ca1160ce4b3efd5b0a71e9072a4c672e49c4732`에서 T10 재평가 저장/출처 처리와
T28 CLI의 `--initial-args` 구문 분석이 바뀌었다. 현재 코드와 실제 배포 이미지는 별도 기준이다.

- 표시 경로: 최신 T10 소스를 읽는 별도 로컬 HTTP 소비 시험 10개가 통과했다.
- 보안 authority: 임시 시험 사본에서만 최신 SHA 대상 시험을 활성화한 사전 호환성 실험은
  34개가 통과했다. 원래 12개 허용 기준, 제품 코드, CI matrix는 수정하지 않았다.
  이것은 새 운영 SHA의 정식 자격 등록이나 실제 권한 인수가 아니다.
- T28 driver: 새 원문의 SHA-256은
  `194d203a209f11db7f0e7cf6d1b0a125608ecf837c631cf382f7b13a95f50b09`다.
  기존 `0795f65`의 `e4bc607112512361d4bde4c6022bc59eb21191fdc139ade77b52f50bb013a355`와 다르다.
  새 driver는 실행하지 않았으며 `DurableT28Port`의 허용 SHA도 확장하지 않았다.

T28을 채택할 때에는 원본 CLI를 그대로 우회 실행할 권한과 `--platform-context` /
`--plan-state-command` subprocess 경로를 함께 다뤄야 한다. 기존 T10 reader callback과
PostgreSQL 효과 원장·현재 승인·fencing·복구 권한을 사용한다. lease 만료나 현재 GET 일치만으로
이전 원격 요청이 종료됐다고 판단하지 않는다.

06:37 KST 후속 관측에서 실제 배포 원본은 `87ec6147e4e6ee717c062894ae891ad8abcb27d9`로
바뀌었다. Reader·등록 API·호스트는 새 imageID로 Ready였고 Reader 설정 v2의 내용 해시는
배포·Pod 주석에 일치했다. 같은 방식으로 새 SHA의 로컬 HTTP 소비 10개와 계약 진단 34개를
확인했으나, 운영 허용 목록이나 실제 인증·권한·효과 인수는 갱신하지 않았다.
T28 원문은 `6ca1160c`와 같지만 실제 새 driver 실행을 검증한 것은 아니다.

## 남긴 근거

- [구현·Mac process/PG 검증](development/workload-view-2026-11-07.md)
- [후보 이미지 source·해시·CI](development/workload-candidate-image-2026-11-07.md)
- [콘솔 투영 계약](console-workload-projection.md)
- [인증·권한·네트워크·감사·복구 인수 계획](platform-live-acceptance.md)

원본 로그·해시 manifest·계약 실험·영상은 비공개 로컬 증빙 경로에 보존한다.
공개 문서에는 운영 계정, endpoint, 개인 경로, 토큰과 원문 오류를 싣지 않는다.
