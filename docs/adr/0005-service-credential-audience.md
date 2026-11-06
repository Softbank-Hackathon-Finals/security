# ADR-0005: 플랫폼 T7와 서비스 전용 자격의 audience 경계

- 상태: 개인 환경 구현/로컬 실제 API 검증. 팀 배포는 미인수.
- 요구: CTRL-01·02, POL-01·09, SG-1, SEC-PATCH-05.
- 기준: platform `c225c86cf5e408b5fcd016b0e367d3672d1bac44`.

## 발견

현재 [T7 credentials.py](https://github.com/Softbank-Hackathon-Finals/platform/blob/c225c86cf5e408b5fcd016b0e367d3672d1bac44/infra/envs/rehearsal-access/credentials.py)의
`acquire`는 Secret UID에 결속된 600초 TokenRequest를 만든 뒤 대상 API에 새 토큰으로
SelfSubjectReview를 요청한다. 이는 API 자격을 검증하는 기존 목적에 맞는다.
보안 서비스용 audience는 Kubernetes API의 허용 audience와 다르므로 이 마지막 요청을
통과하지 못한다. 기존 ExecCredential 형식의 재사용과 발급 경로의 실제 호환성을 구분한다.

## 결정

클러스터 안의 호출자는 기존 워크로드 ServiceAccount에 별도 projected serviceAccountToken
볼륨을 추가한다. audience는 등록한 보안 서비스 값, expirationSeconds는 600, 해당 소비자
컨테이너에만 readOnly mount한다. `MountedTokenCredential`은 요청마다 현재 파일을 읽으며
파일 유실·만료 때 다른 자격으로 대체하지 않는다. Kubernetes/kubelet이 발급과 회전을 맡는다.
서비스의 TokenReview용 API 토큰과 소비자의 서비스 토큰은 서로 다른 자격이다.

예시 Pod template 조각은 기존 GitOps 명세에 검토 후 합성한다. 아래 객체만으로 실행 가능한
Deployment가 아니며, 기존 컨테이너/볼륨/ServiceAccount 설정을 덮어쓰지 않는다.

```yaml
spec:
  volumes:
    - name: security-review-identity
      projected:
        defaultMode: 0440
        sources:
          - serviceAccountToken:
              path: token
              audience: registered-security-review-audience
              expirationSeconds: 600
  containers:
    - name: existing-platform-consumer
      volumeMounts:
        - name: security-review-identity
          mountPath: /run/security-review-identity
          readOnly: true
```

기존 Pod의 runAsUser/fsGroup 및 volume 소유권에 맞춰 읽기 권한을 인수한다. 파일 내용을
환경 변수나 Secret YAML에 복사하지 않는다. 서비스는 이 소비자의 실제 SA UID와 범위를
별도 등록해야 한다. Pod UID 결속이 있어도 서비스 권한은 SA 단위 등록임을 유지한다.

클러스터 외부 호출자는 지금 자동 지원한다고 주장하지 않는다. 필요한 경우 플랫폼 T7에
서비스 자격용 검증 경로를 추가하되 기존 issuer enrollment·bound Secret UID·제한된
TokenRequest 정책을 재사용해야 한다. 서비스 검증 성공을 API SelfSubjectReview로 위장하지
않고, 기존 API 자격 발급 동작도 바꾸지 않는다. 해당 플랫폼 변경은 인계 사항이다.

복수 audience 토큰, 보안 서비스의 API audience 수용, 새로운 장기 토큰/자체 issuer는
선택하지 않는다. 서로 다른 사용처의 권한을 합치는 편의보다 경계를 유지한다.

## 검증과 제한

`tests/integration/test_platform_t7_credentials.py`는 고정 플랫폼의 실제 `acquire`를 읽는다.
issuer의 그룹 응답과 접근 경로는 시험 shim이며 Tailscale 프록시를 검증한 것이 아니다.
발급/대상 bearer 인증/TokenReview는 실제 로컬 Kubernetes API가 수행한다.
API audience의 T7 성공과 서비스 거부, 서비스 audience의 최종 API 거부를 각각 시험한다.
Pod-bound 토큰, projection 명세의 API 수락, 보호된 파일 교체와 매 요청 재조회도 시험한다.
실제 kubelet 회전, 워크로드 실행, CNI, 대상 EKS/RKE2의 경로·권한 인수는 남아 있다.

근거: [Kubernetes ServiceAccount 토큰 문서](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/),
[ServiceAccount 보안 문서](https://kubernetes.io/docs/concepts/security/service-accounts/).
