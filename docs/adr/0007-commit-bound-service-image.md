# ADR-0007: 고정 소스와 최소 입력으로 서비스 이미지 검증

- 상태: 구현, 실제 CI 컨테이너·TLS·철회·T10 initial/post_apply 연결 검증. 운영 배포 인수 전.
- 요구: SEC-PATCH-05·06·10, CTRL-01·02·07, POL-03·09·11.
- 플랫폼 기준: `c225c86cf5e408b5fcd016b0e367d3672d1bac44`.

## 결정

패키지만 전달하면 운영자의 빌드 환경에 따라 서비스가 달라질 수 있다. 기존 플랫폼의
`services/platform-events/deploy/approval/Dockerfile`과 같은 Python 3.12.16 slim-trixie
이미지 digest를 사용하고, `uv.lock`의 **service extra만** 해시가 있는 requirements로
내보낸다. Docker는 실행 의존성을 binary wheel로만 설치한다. 개발 도구·AWS SDK·FastAPI는
서비스 venv에 넣지 않는다. 바탕 이미지에 포함된 전역 도구까지 제거했다는 의미는 아니다.

후속 ADR-0014에서 전역 pip의 실제 취약점을 확인했다. 현재 구현은 build installer를
기존 lock의 pip 26.2.2 wheel hash로 고정하고 최종 이미지의 pip/ensurepip 및 전역 Python package를
제거·검증한다. OS 전체 최소화나 취약점 부재를 뜻하지 않으며 실제 v2 검사는 아직 BLOCK이다.

`scripts/prepare_service_image.py`는 깨끗한 정확한 Git commit을 임시 공간에 archive하고
잠금 개발 환경의 backend로 wheel을 만든다. Docker에 전달하는 별도 새 디렉터리는
Dockerfile, wheel, requirements, 공개 manifest만 포함한다. 작업 폴더·Git 메타데이터·로컬
설정·자격 파일은 Docker build context에 들어가지 않는다. 기존 출력 경로를 덮어쓰지 않는다.
manifest는 source/lock/wheel/requirements/template/preparation digest를 묶는 진단 자료이며
서명된 공급망 attestation, 승인, 실행 권한 또는 정식 발행을 뜻하지 않는다.

런타임 기본 사용자는 10001:10001이다. 배포 명세의 read-only root, capability 제거,
no-new-privileges에 맞춰 CI에서 network=none으로 실제 이미지의 import·기본 UID·권한·쓰기
거부를 검사한다. 이어서 독립 컨테이너를 실제 격리 PostgreSQL과 로컬 TLS TokenReview
시험 서버에 연결해 현재 판정과 issuer 철회 후 거부를 검사한다.

두 번째 시험은 비밀 파일을 읽을 수 있도록 **비-root CI runner UID로 실행**하고,
본인이 만든 test directory·감사 파일·private PG socket만 mount한다. loopback 시험을 위한
host networking을 사용하므로 UID 10001의 실제 Secret/PVC 권한, CNI, kubelet token rotation,
멀티 노드 연결 또는 팀 배포 환경을 인수한 것으로 해석하지 않는다. 기본 UID 시험과 서비스
연결 시험의 범위를 분리한다. 실제 클러스터에서는 생성 명세의 UID/fsGroup과 NetworkPolicy를
별도로 검증해야 한다.

## 실행

잠금 개발 환경과 uv 0.13.6을 사용하고 source를 commit한 상태에서:

```sh
uv sync --locked --extra dev --extra platform-test --no-install-project --no-build --python 3.12
.venv/bin/python scripts/prepare_service_image.py --output /tmp/new-service-image-context
docker build --platform linux/amd64 --iidfile /tmp/new-service-image-id \
  --label "org.opencontainers.image.revision=$(git rev-parse HEAD)" /tmp/new-service-image-context
```

CI `service-image`는 기존 package·현재 일곱 플랫폼 계약·secrets 성공 후 이 과정을 수행한다.
레지스트리에 push하지 않으며, 공개 build inputs와 **local image ID**만 artifact로 보존한다.
local image ID는 레지스트리 manifest digest가 아니다. 운영 배포에 쓰려면 팀의 기존 이미지
발행/서명/검증 경로를 통해 registry digest를 받고 그 값을 review manifest에 지정해야 한다.

## 검증 근거와 한계

- 공식 Docker Registry 읽기 조회로 base index digest와 linux/amd64 manifest를 확인했다.
  Python 환경값은 3.12.16이며 플랫폼의 고정 base와 일치한다.
- `uv export --locked --offline --no-default-groups --extra service --no-emit-project`는
  현재 lock에서 성공했다. 자동 의존성 갱신을 하지 않는다.
- 변경 후 로컬 ruff 및 Git whitespace 검사 통과. `893ddff`의
  [CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42207161356)에서 실제
  이미지 build, 기본 UID 10001·capabilities 0·no-new-privileges·루트 쓰기 거부와
  TLS/issuer 철회 시험 1 PASS(1.93초)를 확인했다. 서비스 venv에는 자체 패키지와
  실행 의존성 9개만 있었다. 이후 네 번째 플랫폼 기준의 initial/post_apply 10개 연결
  시나리오를 image job에 추가했다. 로컬 Docker daemon은 시작하지 않았다.
- 해시 고정 자체는 취약점 부재를 증명하지 않는다. 새 권고문과 dependency/base 갱신은
  별도 평가·시험을 거쳐야 하며 이번 image test를 22개 보안 통제 전체 PASS로 확대하지 않는다.
