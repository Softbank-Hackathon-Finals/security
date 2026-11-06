# 데모용 맥에서 이어받기

2026-11-07 KST. 개인 검증 코드는 준비됐고 실제 플랫폼 로그인·인수는 후속이다.
현재 허용 범위는 **공용 리소스를 변경하지 않는 읽기 전용 확인**이다. 류지환 님의 일괄 배포가
끝나고 확인할 시점을 맞춘 뒤 진행한다. 아래 명령은 이번 작업에서 실행한 운영 결과가 아니다.

## 1. 코드·검증 결과 선택

| 대상 | 고정 기준 / 결과 |
|---|---|
| security 코드 | `546f6e0482cc06fa32f00ea8d554522551a84beb` |
| Sova 소비 코드 | `a177276761f601428d54df57dc4a2000274c6ac1` |
| platform 개발 계약 | `0795f65e24f58e43545b16b97757efcc0923fd4a` |
| 선언된 T10 호스트 이미지 원본 | `445848d2ed9878e31eb6f5aabad0575c61739b47` — 실제 rollout은 별도 대조 |
| 이미지 검증 CI | [42265872242](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42265872242), 두 native 아키텍처 PASS |
| 소비 검증 CI | [42266814087](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42266814087), process/container 각각 44 PASS, T28 최신 36 PASS |

`security`·`sova-test`의 `feature/security-service-integration`에 개발 기록과 원본 증거가 있다.
문서 추가 커밋과 검증한 코드 source를 구분한다. 같은 `0.11.0` 이름만 보고 main의 이전 wheel을
선택하지 않는다. 소스·lock·wheel hash를 함께 확인한다.

## 2. 맥에 맞는 이미지 받기와 로컬 대조

Apple Silicon은 `arm64`, Intel Mac은 `amd64` artifact를 선택한다. Rosetta 터미널의 표시만으로
결정하지 말고 Docker 실행 환경의 실제 아키텍처도 확인한다. 이번 두 이미지는 각각 native runner에서
검증했으며 cross-architecture 에뮬레이션 결과가 아니다. GitHub와 Docker 도구의 로그인/준비는
해당 맥에서 수행한다. AWS나 Kubernetes의 로그인을 이미지 다운로드에 사용할 필요는 없다.

```sh
gh run view 42265872242 --repo Softbank-Hackathon-Finals/security \
  --json headSha,conclusion
# headSha가 위 security 코드이고 conclusion이 success인지 확인한다.

# Apple Silicon 예시. Intel이면 arm64를 amd64로 바꾼다.
demo_arch=arm64
demo_image_dir=$(mktemp -d "${TMPDIR:-/tmp}/sova-image.XXXXXX")
gh run download 42265872242 --repo Softbank-Hackathon-Finals/security \
  --name "sova-security-qualified-image-${demo_arch}-546f6e0482cc06fa32f00ea8d554522551a84beb" \
  --dir "$demo_image_dir"
shasum -a 256 "$demo_image_dir/image.tar.gz"
```

| 아키텍처 | image.tar.gz SHA-256 | local image config ID |
|---|---|---|
| arm64 | `26c9a4cf3f41f2e938ff0c3a35798eb4f98cda0bef607d2950f2cdb5c2c929d6` | `sha256:be377e9a625ebd4620bb284a95a3848132775c775288daa4a263f65416b61bb2` |
| amd64 | `e06f11ec00dc4b3bc164185a4143593a38cc57a17b1e4722c71f516f6c2e0cc1` | `sha256:f04d687736ceaa58925dd9de77d34d8513fbdcc20d6ceefc4bcba46b267d0132` |

체크섬이 위 값과 다르면 중단한다. 같이 받은 `archive-provenance.json`의 source/platform/정책과
[고정 원본](https://github.com/Softbank-Hackathon-Finals/security/blob/e2709ee075c62b6c7b2c5249b50a6ea114e972ff/docs/evidence/service-image-scan-2026-11-07/README.md)을 대조한다.
필요한 로컬 Docker 반입은 `docker load --input "$demo_image_dir/image.tar.gz"`이며, 반입 뒤
`docker image inspect`로 위 config ID·OS/architecture·`org.opencontainers.image.revision`을 확인한다.
서비스 기동에 필요한 전용 DB/CA/현재 신원은 [서비스 안내](security-review-service.md)를 따른다.
이 단계는 플랫폼 배포를 하지 않는다. artifact는 14일 보존이며 만료되면 임의 동명 버전으로 대체하지 않는다.
실제 발행 시에는 새 스캔과 기존 플랫폼의 서명·registry digest·승인 경로가 필요하다.

## 3. 실제 플랫폼은 지정된 경로로만 확인

- AWS profile은 **`bravo-personal` SSO**다. `default`는 다른 계정이므로 사용하지 않는다.
- 플랫폼 AWS RKE2는 기존 **SSM API 포워딩** 경로다. 임의 endpoint나 다른 kubeconfig를 추정하지 않는다.
- `.local-tools/team-test.json`·`bravo-target-test`·팀 접속 ZIP은 **온프렘 목적지용**이다.
- T10 호스트·Reader·등록 API의 대상 namespace는 **`platform-state`**다.

기존 platform의 `workon target-check t10-db --route platform-rke2-ssm` 경로와 등록된 대상·계정·
클러스터 UID를 확인한다. AWS 명령마다 `--profile bravo-personal`을 쓰거나 해당 명령에만
`AWS_PROFILE=bravo-personal`을 지정한다. 로그인 이후의 실제 연결은 기존 플랫폼 안내를 따른다.

등록 대상과 일치하는 맥의 context를 확인하고 다음 종류의 읽기 전용 자료만 수집한다.

1. Deployment/Pod의 Ready 상태, 배포 revision, 실제 imageID. 개발 SHA와 runtime source를 별도로 기록한다.
2. Reader 이미지와 설정 v2가 같은 rollout인지, 관련 Service/EndpointSlice가 준비됐는지 확인한다.
3. ServiceAccount UID, Role/RoleBinding 및 NetworkPolicy의 현재 선언을 확인한다.
4. 기존 T10 읽기 API와 T24 감사 전달 상태를 확인한다. 과거 PASS의 시각·만료·계획 문맥을 보존한다.

전체 Secret·환경 변수·DSN을 출력하지 않는다. `apply`, `patch`, `rollout restart`, `exec`, 역할 변경,
토큰/키 철회, 백업/복원, 컷오버와 실제 거부 탐침은 현재 읽기 전용 확인에 포함하지 않는다.
정책 선언이 존재하거나 Pod가 Ready라는 이유만으로 실제 거부·복원 시험을 PASS 처리하지 않는다.

## 4. 인수 결과를 남길 형식

각 항목에 확인 시각, 실제 source/image digest, 환경 revision, 수집 방법, 익명 대상 표식,
원본 hash, 결과와 미검증 이유를 남긴다. 비공개 원문에만 실제 endpoint·사용자 식별자를 보관한다.
인증·권한·네트워크·감사·복구의 실제 인수 조건은 [실환경 실행안](platform-live-acceptance.md)의 표를 따른다.

T28의 개인 포트는 기존 원장으로 재호출을 차단하지만 원본 플랫폼 CLI를 자동 교체하지 않는다.
플랫폼 조립과 직접 실행 IAM/RBAC 제한, 지연 요청 terminal/fencing 확인은 별도 인수다.
원장 결과가 불명확하면 재적용하지 않고 보류한다. 상태 변경이 필요한 시험은 전용 대상·시험 창이
확정된 뒤 기존 승인 절차에서 시행한다. 현재 다섯 실환경 항목은 **미검증**이다.
