# 2026-11-07: 콘솔 투영 후보 이미지 자격

상태: PR CI·산출물 대조 완료. 레지스트리 발행·이미지 실행·플랫폼 배포·운영 인수 없음.

## 기준과 출처

- [Draft PR #3](https://github.com/Softbank-Hackathon-Finals/security/pull/3)
- [검증 실행 42289946903](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42289946903)
- PR 코드 커밋: `f711647b5ef5227716b2654127457688d1ce9446`
- 당시 PR head: `d0a11b6ccdc1617c93c85a79e3ef2445426b8e9c`
- **이미지 빌드 원본:** PR 검증용 merge commit `417246440dceb1a3df5646cccbedd38fb8914436`

이미지는 위 merge commit에서 빌드됐다. PR head, 기존 인계 코드 `546f6e0`, 운영 이미지
원본 `445848d`와 바꿔 적지 않는다. 이후 문서 커밋도 이 이미지에 포함된 것으로 간주하지 않는다.

## CI 결과

| 검사 | 결과 | 한계 |
|---|---|---|
| secrets | PASS | 해당 CI의 검사 범위 |
| Python 3.11·3.14 패키지 시험 | PASS | 실제 클러스터 인증·권한 인수 아님 |
| 플랫폼 고정 기준 계약 12개 | PASS | 고정 코드 계약, 현재 배포 상태의 증명 아님 |
| native amd64·arm64 이미지 | 각 PASS | 서로 다른 아키텍처의 독립 빌드·검사 |
| review-endurance | SKIPPED | 선택 실행 항목. 완료로 합산하지 않음 |

두 이미지 모두 Trivy 0.76.2, 취약점 DB 갱신 시각 `2026-11-06T18:59:52Z` 기준으로
CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN 발견이 각각 0건이고 이미지 정책 PASS다.
이 결과는 검사 시점·DB·범위에 한정된다.

## 다운로드와 대조

후보 산출물을 실행하지 않고 다음을 대조했다.

1. GitHub artifact ZIP의 digest와 실제 다운로드 바이트.
2. 내부 이미지 archive의 SHA-256·크기와 생성 기록.
3. 이미지 manifest가 참조하는 config JSON의 SHA-256과 아키텍처·revision.
4. 취약점 보고서의 config ID와 해당 이미지 config.
5. source wheel에 새 `console_workload` 모듈이 포함되고 검토한 코드와 같은 바이트인지.

| 아키텍처 | 이미지 artifact ID | 이미지 archive SHA-256 | config ID |
|---|---|---|---|
| arm64 | `13539402683` | `e8584ad19f2a5b433666514b263715c3f574b8d8d7d3173d318986786ec1c99c` | `sha256:b3b49204a415c9454bd21a47c7ba554ee7ac60f723f5eb7aeab340b55685cebf` |
| amd64 | `13538824391` | `8c5a7222bb1ceb5ad7ebb2168b5f4965bec903bbd45ed6136fe0ae2aea7b9b2d` | `sha256:13f2b425d770323ef5f6872d097fd7b7803ed21d3ad811cc700cc00501375699` |

입력/보고서 artifact는 arm64 `13539736883`, amd64 `13538754462`다.
GitHub의 14일 보관 기간에 따라 만료되므로, 다운로드한 원본·검사 요약은 접근 제한 로컬
증빙 경로에도 보존한다. 만료 후 다른 버전으로 자동 대체하지 않는다.

위 config ID는 registry distribution digest가 아니며, 해시 일치는 서명된 provenance나
운영 배포 승인을 대신하지 않는다. 이 후보의 `release_authorized`는 false다.

## 아직 하지 않은 것

- 후보 이미지를 Docker에 load하거나 실행하지 않았다.
- 후보 이미지를 레지스트리나 팀 클러스터에 배포하지 않았다.
- 이 후보 이미지의 90분 지속 시험을 하지 않았다. 기존 `4511a43`의 결과를 합산하지 않는다.
- 실제 projected token·IAM/RBAC 철회·네트워크 거부·감사 보존·복구 인수는 남아 있다.

이전 `546f6e0` 생산자의 Mac process 소비 시험 44개와 T28 시험 36개는
[별도 개발 기록](workload-view-2026-11-07.md)에 있다. 그 결과로 새 이미지 실행을 대체하지 않는다.
