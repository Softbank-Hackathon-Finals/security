# 실제 플랫폼 인수 실행안

기준 platform `0795f65e24f58e43545b16b97757efcc0923fd4a`, 2026-11-07 KST.
현재 상태는 **데모용 맥에서 로그인·실환경 확인하도록 인계**다. 사용자가 실제 인수를 후속으로
지정했고, 현재 플랫폼 일괄 배포와 겹치는 변경을 금지했다. 개인 CI의 PASS를 아래 결과로 옮기지 않는다.
이번 작업은 기존 플랫폼의 배포·발급·승인·실행·감사·복원 도구를 소비한다.

## 먼저 고정할 대상

사용자 확인으로 대상과 경로를 구분했다.

- **플랫폼 AWS RKE2:** `bravo-personal` SSO profile, 기존 SSM API 포워딩 경로.
  T10 호스트·Reader·등록 API의 namespace는 `platform-state`다. `default`는 다른 계정이므로 사용하지 않는다.
- **온프렘 목적지:** `.local-tools`의 `team-test.json`·`bravo-target-test`와 팀 접속 ZIP은 이 대상용이다.
  플랫폼 인수에 사용하지 않는다. 앞서 ZIP 경로의 DNS가 실패한 결과는 플랫폼 네트워크 시험이 아니다.
- **현재 범위:** 공용 리소스 변경 없는 읽기 전용 확인. 류지환 님의 일괄 배포 종료와 시험 시점을
  맞춘 뒤 데모용 맥의 실제 로그인으로 확인한다. 대신 연락하거나 배포를 시작하지 않았다.

[최신 플랫폼 사전 점검](https://github.com/Softbank-Hackathon-Finals/platform/blob/0795f65e24f58e43545b16b97757efcc0923fd4a/docs/operations/happy-path-preflight.md)의
등록된 SSM 경로를 먼저 확인한다. 아래는 후속 실행 형식이며 이번 세션의 성공 결과가 아니다.

```sh
AWS_PROFILE=bravo-personal ./workon target-check t10-db --route platform-rke2-ssm
```

SSO 계정·클러스터 UID·SSM 대상·로컬 포워딩 포트가 등록된 플랫폼 대상과 일치해야 한다.
맥의 기존 context 이름을 확인한 뒤 `platform-state`의 Deployment/Pod 신원·상태·이미지 digest,
ServiceAccount UID, 관련 RBAC/NetworkPolicy와 ConfigMap의 참조·revision을 읽는다.
Secret 값·전체 환경 변수·DSN은 출력하지 않는다. Reader 설정 v2와 이미지가 같은 rollout인지,
호스트·등록 API가 준비됐는지 확인한다. rollout을 유도하는 patch·restart·apply·exec는 수행하지 않는다.

아래 실제 거부·철회·복구 시험 중 자원 생성이나 상태 변경이 필요한 부분은 현재 읽기 전용
확인으로 대체할 수 없다. 후속 전용 시험 창·소유 리소스가 정해진 뒤 시행하고 그전에는 UNKNOWN이다.

## 다섯 인수 항목과 필요한 원본

| 항목 | 실행할 허용·거부 대조 | 완료 근거 / 현재 남은 조건 |
|---|---|---|
| 인증 | 실제 projected token 회전, 단일 서비스 audience, 원래 수명 ≤600초, 현재 SA UID, 만료·UID 교체·grant 철회 | 기존 kubelet/T7 경로로 발급한 현재 신원과 서비스 응답. 합성 TokenReview는 제외. 외부 T7의 API SelfSubjectReview는 서비스 audience 검증과 다르므로 기존 API 토큰을 허용해 우회하지 않음 |
| 권한 | 같은 환경의 허용 요청을 전후 확인하고 타 tenant·미등록 workload·쓰기/Secret/exec·직접 반영 경로를 실제로 거부 | 실제 IAM/RBAC와 전용 reader의 SELECT/FORCE RLS·PUBLIC TEMP/대형 객체 생성 거부. opt-in cutover 역할의 의도된 exec 허용을 baseline blanket deny로 오판하지 않음 |
| 네트워크 | 실제 서비스 TLS, TokenReview, DB/pooler의 허용 경로; 타 DB·평문·잘못된 CA/이름·미허용 workload의 거부 | 같은 UID/Service/EndpointSlice/정책·유효 창의 정상 대조군과 오류 분류. timeout 하나만으로 차단 PASS를 만들지 않음. 직접 DB와 pooler를 별도 기록 |
| 감사 | T10의 실제 커밋 이벤트→기존 T24 writer→Object Lock readback→독립 reader 체인 검증; 같은 origin 재전송/변조 대조 | source event ID·plan/run/operation·record hash·VersionId·COMPLIANCE 보존·전달 상태. 서비스 computed JSONL은 전달/승인/실행 완료가 아님 |
| 복구 | 독립 host hold 유지→정확한 백업 ID로 새 UID/격리 영역에 복원→최신 철회 재등록→실제 내용/업무/효과 조정→명시적 해제 | source/backup/restore UID, 시간, 실제 데이터 비교, 측정 RPO/RTO, 과거 trust 복원 뒤 신규 실행 거부. Pod 재시작·Ready·행 수만으로 전체 복구 PASS를 만들지 않음 |

각 항목은 app/environment revision·정책 버전·계획 digest·승인 ID·이미지 distribution digest와
결속한다. 사후에는 실제 application/operation ID 및 적용 이후의 새 관측이 필요하다.
원본·수집기 신원·시각·method·허용 대조가 없으면 UNKNOWN이며 전체 인수는 보류한다.

## 기존 운영 구현에서 먼저 확인할 차이

**T24:** 최신 SHA의 [기존 서비스](https://github.com/Softbank-Hackathon-Finals/platform/blob/0795f65e24f58e43545b16b97757efcc0923fd4a/services/audit-log/README.md)는
T10 SSE를 구독하는 `bravo-audit follow`와 실제 버킷 시험을 이미 제공한다. 이 경로를 재사용한다.
저장소의 체인에서 재개하고 마지막 이벤트를 다시 대조하는 계약을 유지하며 별도 cursor/writer를 만들지 않는다.
상시 배포와 런타임 writer 주체 등록은 아직 후속이라고 기록돼 있다. 현재 배포 상태를 읽어서 확인한다.
보안 판정 서비스에 S3 writer 자격을 추가하지 않는다. writer 역할의 신뢰 주체가 실제
런타임에 등록됐는지 먼저 확인한다. 버킷 정책/Lock 변경 거부 탐침은 호출자의 현재 신원과
소유 시험 대상이 확인된 범위에서만 수행한다. 기존 실백업·감사 객체를 삭제 대상으로 쓰지 않는다.

**T35:** 기준 SHA의 [목적지 백업 안내](https://github.com/Softbank-Hackathon-Finals/platform/blob/42811da4cf19ce941491d4794ab49790881dc409/infra/envs/target-backup/README.md)는
목적지 적용 전이며 TLS·신원·복원 namespace 네트워크·용량·Barman 플러그인이 선행한다고
기록한다. 현재 환경을 읽어 이 조건부터 확인한다. 임의로 운영 DB를 patch하거나 단일
인스턴스를 재시작하지 않는다. 실제 필요 변경은 정확한 대상·diff·영향 범위를 정한 뒤
기존 플랫폼 변경 절차로 넘긴다. 개인 환경에서 만든 정상 결과로 이 선행 조건을 채우지 않는다.
0795f65의 출발지 기록은 저장소/플러그인/WAL 경로 적용까지 진행됐지만 실제 백업·복원은 아직이며,
Executor의 AWS 자격 부재로 일부 판정이 UNKNOWN임을 명시한다. 이 제한도 운영 결과에 보존한다.

**T28:** 개인 `DurableT28Port`는 최신 고정 driver를 기존 effect journal에 연결한다.
원본 `happy_path.py` 자체는 바뀌지 않았다. 플랫폼 조립 시 기존 T10 승인/잠금·영속 접수와
현재 권한 조회를 주입하고, 직접 하위 명령으로 우회할 수 있는 실행 자격도 제한해야 한다.
호출자 사망·lease 만료·현재 GET 일치만으로 원격 지연 요청의 종료를 추정하지 않는다.
공급자의 terminal/cancel/fencing 증거를 기존 recovery authority가 확인한 뒤 조정한다.

## 보존과 종료

실제 endpoint·토큰·DSN·전체 원문 오류는 비공개 영수증 경로에 한정한다. 공개 기록에는
요구사항 ID, 기준 SHA, 대상의 익명 표식, 실행/판정/정리 상태, 원본 hash, 미검증 사유를 남긴다.
이번 실행이 만든 객체만 이름·실행 표식·UID를 대조하여 정리한다. 확인할 수 없는 객체를
재생성하거나 접두사만으로 삭제하지 않는다. 감사/백업 보존 정책은 정리를 위해 완화하지 않는다.

완료 상태는 `개인 CI 검증`, `실환경 shadow`, `실환경 집행`, `복구 인수`를 구분한다.
현재 다섯 항목의 실제 플랫폼 결과는 **미검증**이며, 이 문서 작성은 운영 인수 완료가 아니다.
