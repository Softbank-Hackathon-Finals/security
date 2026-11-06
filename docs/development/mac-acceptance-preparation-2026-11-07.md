# Mac 인수 준비: 고정 산출물 대조와 플랫폼 차이

관측일: 2026-11-07 KST. 상태: **로컬 준비 완료, 실제 플랫폼 관측 미실행**.

사용자는 일괄 배포가 진행 중이거나 시점이 미확인이라고 답했고, 로컬 준비만 진행하도록
범위를 확정했다. SSM 터널을 열지 않았으며 Kubernetes API·제품 API 조회, exec,
배포·restart·patch·자격 발급/철회·복원·컷오버를 수행하지 않았다. Slack 연결·전송도 없다.

## 1. 기준을 분리한 결과

| 구분 | SHA / 의미 |
|---|---|
| 받은 security 문서 | `871d38aa2fa388d9a2831cbfb07ed24d6d14e413` |
| 검증된 security 코드 생산자 | `546f6e0482cc06fa32f00ea8d554522551a84beb` |
| 받은 sova-test 문서 | `ed1a9ad4e05325cfc7013692f63c973165980e36` |
| 최종 소비 CI 소스 | `a177276761f601428d54df57dc4a2000274c6ac1` |
| 인계 시 platform 개발 계약 | `0795f65e24f58e43545b16b97757efcc0923fd4a` |
| 이번에 고정해 읽은 develop | `c364e6284d2e635ff86001e2feac88560ed23ebc` |
| GitOps 호스트·Reader 이미지 선언 원본 | `445848d2ed9878e31eb6f5aabad0575c61739b47` |
| 실제 운영 imageID·source | **미관측** |
| 별도 90분 시험 소스 | `4511a433d9a8af8bab7426cb934842a96bca5290` — 최종 이미지 시험과 합산하지 않음 |

인계 문서 SHA와 생산자 사이의 `src`, `pyproject.toml`, `uv.lock`에는 차이가 없었다.
기존 Mac의 security main을 덮어쓰지 않고 인계 브랜치를 별도 worktree에서 열었다.
sova-test는 인계 브랜치로 별도 clone했다. 팀 platform은 detached 읽기 사본만 만들었다.

## 2. 현재 개발 계약의 차이

`0795f65..c364e628`에는 merge commit을 포함해 11개 커밋, 20개 파일 변경이 있다.
주요 변경은 T24 공개 감사 reader·영수증 기반 등록, T36 첫 UNKNOWN 창 처리,
T8 출발지 업로드 중지/복원 도구, Product Reader 이미지 pin이다.

다음 경로는 Git 객체가 동일하다. 이 사실만으로 최신 develop 전체의 소비 자격을 부여하지 않는다.

| 경로 | 양쪽 Git 객체 |
|---|---|
| `services/platform-events` | `c30ae6bd87d10a3e76cbd0ef5793ffdc372c520b` |
| `services/control-gate` | `00f6b445e9482a886524fa69ea0d61b2292caf2b` |
| `scripts/happy_path.py` | `8a3e3993682f31ce262e1a82e21c4f11d60e75c5` |

T28 파일 SHA-256은 `e4bc607112512361d4bde4c6022bc59eb21191fdc139ade77b52f50bb013a355`다.
관측 패키지 등 주변 의존성은 변경됐으므로, 같은 파일이라는 이유로 기준 SHA를 바꾸지 않았다.

현재 GitOps 선언(`infra/gitops/environments/development/*-image.json`):

| 대상 | image digest | sourceRevision |
|---|---|---|
| registration / workflow-host | `sha256:2243e1b690a1c5bc513b1eff91d3e8d61eca9a5951870e696718e384e1d37733` | `445848d2ed9878e31eb6f5aabad0575c61739b47` |
| product-reader | `sha256:6fd9fe9242dad0c57cfa359f95c3040ec039ec8545a3cf37f75073736c53426e` | 동일 |
| rehearsal-host | `sha256:56cd42d3d5213bab93b046e23e7dfb6433d19d2c2d12bb065b37be983f41d988` | 동일 |

Reader의 이전 선언은 source `a15a9253e80b4a4b9b152a9423bf20f1e11dd214`,
digest `sha256:3e57fcb8ff96834a84e83efaf9e06ae403217df5a51c27b74dd2831f16f2952e`였다.
[#562](https://github.com/Softbank-Hackathon-Finals/platform/pull/562) 병합은 확인했지만,
이미지와 설정 v2가 실제로 같은 rollout에 반영됐는지는 조회하지 않았다.

현재 platform의 `services`, `operations`, `infra/charts`, `scripts/happy_path.py`에서
`T10ProgramAuthority`, `DurableT28Port`, `sova_security` 연결을 찾지 못했다.
이는 조사한 소스 범위의 결과이며, 운영 배포 부재를 확인한 결과는 아니다.

## 3. Mac·접속 자료 확인

- Mac CPU: arm64. Docker daemon: linux/aarch64. Rosetta 결과로 대체하지 않았다.
- `bravo-personal`의 STS 조회가 성공했고 기존 개인 SSO 역할·등록 계정과 일치했다.
  `default` profile은 사용하지 않았다. 로그인/MFA 재요청은 필요하지 않았다.
- 기존 플랫폼용 개인 kubeconfig, client 인증서, 공개 CA, 등록된 SSM 안내를 찾았다.
  로컬 CA SHA-256은 전달받은 지문과 일치했고 TLS 검증 생략은 없었다.
  개인 인증서 만료는 2026-11-09 09:05:01 KST다. 파일 존재·만료 확인은 현재 서버 인증 성공이 아니다.
- Session Manager plugin은 기존 로컬 도구 경로에 있다. 기본 PATH에는 없으므로 실제 창에서
  해당 실행에만 PATH를 지정한다. 새로운 전역 설치나 대상 변경은 하지 않았다.
- `workon`은 조사한 Mac 경로에서 찾지 못했다. 문서의 명령이 이 Mac에도 설치됐다고 가정하지 않는다.
  이미 발급된 플랫폼 SSM 안내를 재사용하되, 다음 창에 계정·EC2 대상·클러스터 UID를 재대조한다.
- 온프렘용 `bravo-target-test`, 직접 API ZIP, `team-test.json`은 플랫폼 접근에 사용하지 않았다.

실제 주소·계정·사용자·SSM 대상·클러스터 UID·개인 경로는 비공개 로컬 기록에만 둔다.

## 4. 이미지 대조와 시험 결과

최종 생산자 [CI 42265872242](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42265872242)의
head SHA와 success, native 두 이미지 job 및 12개 계약 job의 성공을 재조회했다.
arm64 artifact `13526499441`은 만료되지 않았고 만료 예정은 2026-11-20T17:58:59Z다.

지정한 artifact만 다운로드하고 archive 안의 manifest/config를 실행 없이 읽었다.

| 대조 | 결과 |
|---|---|
| `image.tar.gz` SHA-256 | `26c9a4cf3f41f2e938ff0c3a35798eb4f98cda0bef607d2950f2cdb5c2c929d6` 일치 |
| archive 크기 | 31,446,621 bytes 일치 |
| config ID | `sha256:be377e9a625ebd4620bb284a95a3848132775c775288daa4a263f65416b61bb2` 일치 |
| OCI revision / OS / arch | 생산자 `546f6e0…` / linux / arm64 일치 |
| archive provenance | 커밋된 원본과 전체 내용 일치 |

`docker load`, 서비스 기동, 새 취약점 스캔, registry 발행·서명은 하지 않았다.
config ID는 registry digest가 아니다. 기존 0건 결과는 당시 DB와 검사 시점의 결과다.

이번 Mac에서 Python 3.12.16과 잠긴 의존성으로 재현한 결과:

| 시험 | 결과 | 범위 |
|---|---|---|
| 고정 platform `445848d`의 기존 bridge 5개 파일 | **34 passed / 15.29초** | 실제 플랫폼 Python 모듈 + 합성 신원/증거 + SQLite |
| 고정 T28 `0795f65` 재시작 + 기존 effect executor | **34 passed / 2.13초** | 로컬 자식 종료·SQLite·합성 파일 효과·loopback 지연 HTTP |
| T28 source guard | `0795f65` 허용, `445848d`와 `c364e628` 거부 | 코드 import 직전 자격 경계, operator 0회 |

이번에는 PostgreSQL T28 2개를 실행하지 않았다. Windows/CI의 36개와 이번 34개를
동일한 시험 결과로 쓰지 않는다. 권한·네트워크·감사·복원 실환경 PASS는 모두 미검증이다.

## 5. T28에서 확인한 연결 선행 조건

`sova-test/src/sova/adapters/platform_t28.py`의 `DRIVER_HASHES`에는 `42811da`와 `0795f65`만 있다.
파일 내용이 같아도 `445848d` 및 최신 develop은 `Unqualified T28 platform commit`으로 거부한다.
security bridge가 허용하는 12개 기준과 T28 driver 허용 목록은 서로 다르다.

따라서 실제 operator entrypoint의 source를 먼저 확정하고 그 정확한 SHA로 별도 자격 시험을
통과해야 한다. 원본 T28을 직접 실행하거나 SHA를 속여 이 제한을 우회하지 않는다.
이 변경, 실제 T10 승인/잠금·PG 소유권 연결, 직접 실행 IAM/RBAC 제한은 팀 변경으로 별도 검토한다.

## 6. 증거와 다음 인계

공개 기계 판독 기록은 [준비 증거](../evidence/mac-acceptance-preparation-2026-11-07/README.md)에 있다.
원본 시험 로그·다운로드 artifact·접속 자료 위치는 비공개 로컬 기록으로 보존한다.
이번 변경은 기록·실행안뿐이며 런타임 코드, 허용 SHA, lockfile, 정책을 바꾸지 않았다.

다음 순서는 [읽기 전용 인수 목록](../platform-readonly-intake.md)을 따른다.
배포 종료와 조회 창이 확인되기 전까지 runtime imageID·Ready·설정 일치·SA/RBAC/NetworkPolicy는
**미관측**으로 유지한다. 그 이후에도 실제 거부·철회·복구 시험은 별도 변경 승인과 전용 창이 필요하다.
