# ADR-0004: 실제 로컬 Kubernetes 인증 계약 검증

- 날짜: 2026-11-06
- 요구: CTRL-01·02·04, POL-01, SG-1, SEC-PATCH-05.
- 상태: 로컬 API/RBAC 실측. 팀 EKS/RKE2 운영 인수와 별도.
- 플랫폼 기준: `b19488e2debbee8bbe120f1309eadbe19df85b6f`.

## 결정

서명된 TokenReview 모형만으로 Kubernetes의 audience·bound object·SA UID·철회 동작을
입증할 수 없다. 기존 생산 코드의 표준 TokenReview 경로를 실제 로컬 API 서버에 연결한다.
서비스용 새 운영 발급기는 만들지 않는다. 플랫폼 T7의 표준 TokenRequest/ExecCredential
경로를 소비하는 설계는 유지한다.

Kubernetes SIG의 공식 envtest 1.35.0 배포본(API 서버와 etcd 3.6.6)을 사용한다.
[공식 배포 목록](https://github.com/kubernetes-sigs/controller-tools/blob/master/envtest-releases.yaml)의
SHA-512와 추출 바이너리 SHA-256을 고정한다. 최신 버전이라는 의미는 아니다. 플랫폼 문서의
RKE2 1.35.9와 minor 계약은 관련되지만, 해당 배포판/패치의 운영 실측으로 대체하지 않는다.

시험은 새 임시 디렉터리·일회용 CA/관리자 인증서·서명 키·etcd로 시작한다. 모두 loopback에만
수신하고 끝나면 자식 프로세스를 종료한다. 기존 kubeconfig나 클라우드 자격증명을 읽지 않는다.
로컬 관리자의 system:masters 인증서는 이 폐기 가능한 시험 제어면에만 사용하며 서비스 계정에
그 권한을 주지 않는다. 서비스는 생성한 배포 명세의 tokenreviews/create 역할만 받는다.

## 검증과 한계

Kubernetes 공식 문서는 TokenReview가 연결된 객체의 현재 상태를 검증하며, 객체 삭제로
bound token이 무효화되는 경로를 설명한다.
[ServiceAccount 관리](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/),
[서비스 계정 토큰](https://kubernetes.io/docs/concepts/security/service-accounts/).
우리는 그 계약을 실제 생성/거부/삭제/재생성으로 시험한다.

- 정상 audience/SA UID는 허용, 다른 audience와 등록되지 않은 UID는 거부.
- bound Secret 삭제 후 거부; 같은 이름의 Secret 재생성으로 이전 토큰이 부활하지 않음.
- SA 삭제·같은 이름 재생성 후 새 UID를 명시적으로 등록하기 전까지 거부.
- 서비스 역할은 Secret 읽기·TokenRequest·Deployment·ClusterRoleBinding 쓰기를 403으로 거부.
  정상 TokenReview 대조군을 먼저 확인하고, 역할 binding 철회 후 판정 불가도 확인.
- 생성한 나머지 Deployment/ConfigMap/Service/NetworkPolicy의 실제 API dry-run 인수.

최초 다섯 시험은 23.96초에 통과했다. `tests/kubernetes_api_support.py`와
`tests/integration/test_kubernetes_review_identity.py`가 재현 경로다. 환경변수
`SOVA_TEST_ENVTEST_DIRECTORY`를 주지 않으면 명시적으로 skip한다. 임의 클러스터 URL로
전환하는 옵션은 제공하지 않는다.

이 환경에는 kubelet·controller-manager·CNI·실제 워크로드·영속 볼륨이 없다. API dry-run은
객체 형식의 수용만 뜻하며 Pod 실행, NetworkPolicy 집행, OpenBao/CNPG/Cloudflare 연동을
뜻하지 않는다. 실제 클러스터에서의 T7 audience·서비스 계정 등록, 노드/Pod 신뢰,
네트워크 우회 차단과 운영 철회 시간은 계속 별도 인수한다.

## 철회 전파 중 보류 검증

Secret 삭제 거부 관측은 10.023초, SA 삭제는 10.017초였다. 독립 서비스·PostgreSQL과
실제 T10 initial/post_apply까지 연결한 추가 시험도 통과했다. 새 Secret UID로 명시적으로
발급한 새 자격만 회복했으며 이전 토큰은 재사용되지 않았다.

삭제 직후 TokenReview가 아직 성공하는 두 시험 창에서 기존 PostgreSQL security hold를
먼저 등록했다. 이후 T10 접수는 각각 0.085/0.087초에 거부됐고 외부 실행은 0회였다.
`test_current_incident_hold_blocks_admission_during_token_revocation_propagation`이 근거다.
이미 dispatch된 실행 취소나 분산 DB의 즉시 원자성은 보장하지 않는다. 운영 host의 현재
승인·보류를 동일 계획 잠금에서 재검사하는 계약을 그대로 유지한다.
