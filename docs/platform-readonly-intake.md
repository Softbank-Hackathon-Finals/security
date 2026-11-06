# 플랫폼 읽기 전용 인수 목록

준비 기준: platform `c364e6284d2e635ff86001e2feac88560ed23ebc`.
현재 상태: **배포 시점 미확인, 로컬 준비만 허용**. 아래는 실행 결과가 아니다.
[Mac 준비 기록](development/mac-acceptance-preparation-2026-11-07.md)과
[실환경 시험 조건](platform-live-acceptance.md)을 함께 사용한다.

## 1. 조회 창을 여는 조건

1. 일괄 배포 담당자의 종료 기록과 조회 가능한 시각을 확인한다. PR 병합·CI 성공·침묵을 종료로 보지 않는다.
2. `bravo-personal`의 현재 계정·개인 역할을 기존 비공개 플랫폼 등록과 대조한다.
   같은 명령 실행 환경에서 자격/endpoint/proxy 덮어쓰기를 제거하고 profile을 명시한다.
3. 기존 SSM API 포워딩 안내의 EC2 대상과 상태를 조회한다. 새 대상이나 온프렘 ZIP으로 대체하지 않는다.
4. 본인 포워드만 연다. 포트가 사용 중이면 기존 세션을 종료하지 않는다.
   개인 인증서·CA·TLS 이름을 사용하고 `kube-system` UID를 기존 등록값과 먼저 대조한다.
5. 일치하지 않거나 조회가 거부되면 정제한 오류와 시각만 남긴다. 자격 발급·권한 변경·다른 계정 우회는 하지 않는다.

`SSM SendCommand`, `kubectl exec`, Job 생성은 조회 준비에 필요하지 않다.
사전 안내의 ConfigMap 생성 권한 확인도 실제 ConfigMap 생성 시험으로 바꾸지 않는다.

## 2. 실제 조회할 객체와 판정 한계

Kubernetes namespace는 `platform-state`로 고정한다. kubeconfig/context는 검증된 개인 경로를
매번 명시하고 요청 시간 제한을 둔다. Secret 값, 전체 환경 변수, DSN, 전체 ConfigMap 내용은 출력하지 않는다.

| 대상 | 수집할 필드·대조 | 아직 증명하지 못하는 것 |
|---|---|---|
| Deployment `t10-registration`, `t10-product-reader`, `t10-workflow-host` | UID, generation/observedGeneration, desired/ready/available, revision, template source/config hash, 이미지, SA, ConfigMap/Secret **참조 이름** | 실제 요청 인증·보안 어댑터 호출·정상 업무 |
| 해당 ReplicaSet·Pod | owner UID 연결, Pod UID/node/phase, init 및 일반 container image/imageID, Ready/restarts, 시작/관측 시각 | Ready만으로 운영 인수 PASS |
| GitOps의 위 3개 pin | 배포 digest와 source annotation 대조. manifest-list와 arch별 manifest digest가 다르면 기존 발행 provenance로 연결 | develop HEAD를 runtime source로 대체 불가 |
| Reader ConfigMap | Pod가 참조한 UID/RV, `reader.json.version=2`, 공개 JWKS 구조, data의 정본 SHA-256; 비공개 원문은 로컬에서만 취급 | annotation 단독으로 내용 일치 증명 불가 |
| Service·EndpointSlice | selector, port/targetPort, endpoint Ready, targetRef UID가 현재 Pod와 일치 | 실제 TLS·정상/거부 통신 시험 |
| SA | `t10-registration`, `platform-runtime`, `t10-workflow-host`의 현재 UID, automount, 해당 Pod 연결 | T7 서비스 audience/TokenReview 정상·철회 |
| RBAC | namespace Role/RoleBinding과 연결된 ClusterRole/ClusterRoleBinding. wildcard·그룹·cluster-admin·pods/exec·Secret·tokenreviews 권한 포함 | 정책 선언을 실제 거부 시험으로 대체 불가 |
| NetworkPolicy | 실제 Pod/namespace selector, ingress/egress, DNS/API/DB/Executor 경로, 다른 정책의 추가 허용 여부 | CNI 집행·기존 연결 종료·timeout의 정책 원인 |
| T10·T24 기존 읽기 접점 | 기존 read 권한의 계획/원문/이벤트·전달 상태, 원 시각·만료·run ID·VersionId·독립 등록 anchor | 새 평가/승인/쓰기/이벤트 생성·복구 |

Reader hash 계산은 기존 `operations/product-reader/reader_config_v2.py:config_sha256`과
`infra/gitops/bootstrap.py`의 compact·sorted JSON 규칙을 재사용한다. 등록 API는
`bravo.dev/source-revision`, Reader/호스트는 `bravo.dev/reviewed-source` annotation을 쓴다.
컨트롤러와 Pod 관측이 조회 중 달라지면 같은 rollout으로 합치지 않고 재조회 필요로 기록한다.

RBAC 조회에서 리소스가 없다는 응답과 권한 거부/부분 목록을 구분한다. ClusterRoleBinding까지
읽지 못하면 전체 권한 분석은 UNKNOWN이다. 등록된 privileged operator의 의도된 exec 권한과
보안 reader의 금지 권한을 구분한다.

## 3. 후속 변경·시험 목록

아래는 **제안·보류**이며 담당자의 실제 배정이나 적용 합의가 아니다. 기존 책임을 유지한다.

| 인수 항목 | 구체적 대상 / 필요한 변경 | 기존 경로를 사용한 시험 | 완료 근거 |
|---|---|---|---|
| 보안 서비스 발행·조립 | T7/T43의 발행 입력에 고정 producer artifact·아키텍처·서명·registry digest 연결. 서비스 위치·SA·DB·보호 mount는 등록 후 확정 | 먼저 읽기 전용 shadow. 기존 `review_manifest.py`는 렌더만 하며 자동 apply하지 않음 | 정확한 배포 imageID/소스/설정·동일 계획의 원문 비교. shadow 일치가 양쪽 PASS를 뜻하지 않음 |
| 인증 | 실제 caller SA UID·전용 audience projected token, 서비스의 현재 TokenReview. 외부 소비자는 T7 audience 검증 확장 필요 | 정상 토큰 전후 대조, 실제 회전·만료·다른 audience/UID·grant 철회. TokenReview 장애는 보류 | 실제 발급/회전/거부 시각·SA UID·응답. 토큰 본문 미보존 |
| 권한·DB | 테넌트 전용 reader와 SELECT/FORCE RLS, DB별 HBA·PUBLIC TEMP/대형 객체 권한, 현재 T10 plan lock을 쓰는 등록/철회 writer | 전용 시험 tenant·DB에서 정상 SELECT와 타 tenant/DB·쓰기·Secret/exec·직접 실행 거부. 공유 DB 변경은 영향 검토 후 | 현재 역할·scope·정상 대조군·명확한 거부 사유. 운영자 권한으로 수행한 성공을 reader 권한 성공으로 세지 않음 |
| 네트워크 | 실제 security-review TLS Service→TokenReview API/DB, caller→service, 필요 시 pooler. 기존 CNI 정책과 합성 허용 여부 | 정상 경로 전후 확인, 잘못된 CA/호스트명·평문·미등록 workload·타 DB 거부를 분리. 직접 DB와 pooler 각각 시험 | 같은 UID/revision/시간창, TLS 실패·인가 거부·policy drop·timeout 구분 |
| T28 실행 연결 | 실제 operator entrypoint SHA 자격, 기존 T10 승인/잠금·PG operation/execution/effect 주입, 하위 CLI 우회 권한 제한 | 효과 전 접수, 호출자 중단·응답 유실·승인 철회·다른 JSONL/명령 인자. 실제 공급자 terminal/cancel/fencing 없으면 재실행 금지 | operation/epoch/명령 fingerprint/실제 readback 결속. 파일 경로만으로 파일 내용 인증 불가 |
| 감사 | T24 `bravo-audit follow`의 런타임 주체·Secret 참조·Object Lock writer 등록. security 서비스에 S3 writer 자격을 부여하지 않음 | 실제 T10 이벤트→T24→S3 COMPLIANCE VersionId→독립 reader. 같은 origin 재전송과 변조는 전용 시험 기록 사용 | `read_run` + 버킷 외부 등록 anchor, 체인·버전·보존·plan/run 연결. JSONL만으로 완료 불가 |
| 복구 | T35/T12 기존 복원·복귀와 독립 host hold, 정확한 백업 ID·격리 대상·네트워크·최신 철회 재등록 | 별도 UID로 복원, 과거 trust 복원에도 실행 차단, 데이터·업무·효과 조정 후 명시적 해제 | backup/restore UID·RPO/RTO·새 쓰기·복구 영수증. Pod Ready/행 수만으로 복구 PASS 불가 |

T28은 `0795f65`와 `42811da`만 driver를 허용한다. GitOps host source인 `445848d`는 보안 bridge의
자격 대상이지만 T28 driver 목록에는 없다. 실제 operator가 어느 소스를 실행할지 확정한 뒤
별도 시험·커밋으로 자격을 추가한다. 이번 준비에서는 목록과 실행 경로를 변경하지 않았다.

T24 최신 공개 읽기 함수는 `services/audit-log/src/bravo_audit/reader.py:read_run`과
`registration.py:registration_from_receipt`다. 기존 follower·anchor를 재사용하고 새 writer나
승인 정본을 만들지 않는다. 실제 상시 배포 여부는 미관측이다.

## 4. 영수증·종료

기록마다 기준 SHA, 실제 대상 표식, 관측 시작/종료, generation/revision/UID, 수집 방법,
원본 hash, 결과와 미검증 사유를 남긴다. 공개본에는 실제 endpoint·사용자·계정·DSN을 넣지 않는다.
상태는 `LOCAL_VERIFIED`, `LIVE_NOT_OBSERVED`, `CHANGE_DEFERRED`로 분리한다.
이번 문서의 체크리스트는 게이트 입력이나 실행 승인으로 사용하지 않는다.

조회가 끝나면 이번 작업이 연 SSM 세션과 로컬 포워드만 정확한 ID/PID로 종료한다.
기존 타인 세션·클러스터 리소스·감사/백업 보존 데이터는 정리 대상이 아니다.
