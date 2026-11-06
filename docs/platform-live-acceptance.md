# 실제 플랫폼 인수 실행안

기준 platform `42811da4cf19ce941491d4794ab49790881dc409`, 2026-11-07 KST.
현재 상태는 **접속 설정 확보 / 본인 tailnet 접속 대기**다. 개인 CI의 PASS를 아래 결과로 옮기지 않는다.
이번 작업은 기존 플랫폼의 배포·발급·승인·실행·감사·복원 도구를 소비한다.

## 먼저 고정할 대상

사용자 다운로드의 기존 팀 접속 ZIP에서 실제 `team-test.json`을 확인했다. 자격 없이 두 HTTPS
경로의 전송을 점검했지만 모두 DNS 해석이 불가능했고, Windows/WSL의 기존 Tailscale 도구도
확인되지 않았다. 이 결과는 네트워크 정책의 정상 차단이나 인증 거부 PASS가 아니다.
본인 Tailscale 접속 뒤 실제 시험 namespace 및 환경 등록을 확인한다.
기존 AWS profile이 플랫폼 계정인지 확인되지 않아 그 계정의 권한을 확대하거나
새 자원을 만들지 않았다. 키·토큰·관리자 kubeconfig를 저장소에 넣지 않는다.

공식 [팀 진입점](https://github.com/Softbank-Hackathon-Finals/platform/blob/42811da4cf19ce941491d4794ab49790881dc409/docs/team-self-service.md)은
다음 순서다. 아래는 명령 형식이며 이번 세션의 실행 결과가 아니다.

```sh
uv run --python 3.12 python scripts/team_runtime.py check --access /private/team-test.json
uv run --python 3.12 python scripts/team_runtime.py run --suite isolation --access /private/team-test.json
uv run --python 3.12 python scripts/team_runtime.py run --suite credentials --access /private/team-test.json
```

첫 `check`에서 본인 ServiceAccount 신원·클러스터 UID·환경 ConfigMap UID/resourceVersion/
내용 해시·노드 아키텍처·현재 이미지 digest를 대조한다. 실패하면 쓰기 시험을 시작하지 않는다.
생성한 실행 ID와 상태 디렉터리를 유지하고, 응답 유실 시 새 `run`을 실행하지 않는다.
동일 ID에 `status`/`cleanup`을 사용하고 각 객체의 UID로 정리한다. `cleanup=CLEAN`은 원 시험
PASS가 아니다. 이 두 suite는 기존 T3/T15 범위이며 보안 서비스 인수 다섯 항목 전체가 아니다.

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

**T24:** 기준 SHA의 [기존 서비스](https://github.com/Softbank-Hackathon-Finals/platform/blob/42811da4cf19ce941491d4794ab49790881dc409/services/audit-log/README.md)는
실제 S3 시험을 완료했지만 T10 상시 연결은 아직 없다고 기록한다. 호스트의 커밋 이벤트와
기존 writer를 연결하고 기존 origin ID 중복 제거·resume·readback을 재사용한다.
보안 판정 서비스에 S3 writer 자격을 추가하지 않는다. writer 역할의 신뢰 주체가 실제
런타임에 등록됐는지 먼저 확인한다. 버킷 정책/Lock 변경 거부 탐침은 호출자의 현재 신원과
소유 시험 대상이 확인된 범위에서만 수행한다. 기존 실백업·감사 객체를 삭제 대상으로 쓰지 않는다.

**T35:** 기준 SHA의 [목적지 백업 안내](https://github.com/Softbank-Hackathon-Finals/platform/blob/42811da4cf19ce941491d4794ab49790881dc409/infra/envs/target-backup/README.md)는
목적지 적용 전이며 TLS·신원·복원 namespace 네트워크·용량·Barman 플러그인이 선행한다고
기록한다. 현재 환경을 읽어 이 조건부터 확인한다. 임의로 운영 DB를 patch하거나 단일
인스턴스를 재시작하지 않는다. 실제 필요 변경은 정확한 대상·diff·영향 범위를 정한 뒤
기존 플랫폼 변경 절차로 넘긴다. 개인 환경에서 만든 정상 결과로 이 선행 조건을 채우지 않는다.

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
