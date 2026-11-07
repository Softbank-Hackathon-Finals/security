# 최신 main과 워크로드 표시 어댑터 통합

2026-11-07. Windows 인계 후 추가된 main의 T14/T33 인수 코드와 기존 워크로드 표시
어댑터를 합쳤다. 운영 플랫폼 배포·실제 격리·복구 완료 기록이 아니다.

## 고정 기준

- 기존 표시 PR head: `b31621b62795806295bf3153ec033c568b026008`.
- main: `d7f752b6ef9dec18f198d2e3760a08a1370f71ea`.
- 통합 커밋: `39e923a8704b64fe1493ac5a282783f5ec5231d8`.
- 콘솔 통합: platform `01abd293`, develop `ef774805`와 기존 Sova UI `86d12aed`를 통합.
- 실제 플랫폼 imageID와 일치한 GitOps source: `adde5804823288e8b437ffb36494cfb5520800c7`.

main의 정규화·인수 목록·인증 재검사 코드를 유지하고 별도 구현을 만들지 않았다.
기존 source `4511a43`의 90분 지속 시험, `546f6e0`의 이미지 자격, 이전 PR CI는 모두
이 통합 커밋의 이미지 자격과 구분한다. 이번에는 새 이미지 실행·배포·90분 시험을 하지 않았다.

## 검증과 재현

- 통합 security 단위 시험 **872개 통과**.
- `scripts/qualify_console_projection.py`는 명시한 두 checkout의 HEAD·변경 여부와
  실제 import 위치를 확인한다. 실제 T10 SQLite/HTTP·security 투영·콘솔·JS 소비자를
  사용하며 신원·권한·스냅샷만 로컬 fixture다.
- 14개 HTTP 경로: 정상, 무인증, 다른 tenant, 읽기 권한 없음, 생산자 철회,
  원문 hash 불일치, 생산자 SHA 불일치, 다른 환경, 읽기 중 계획 변경,
  읽기 중 생산자/권한 회수, 연결 단절, 만료, POST 거부.
- 정상 결과의 20개 노드에는 구성 경고 2개만 표시한다. 건강·통신·격리·복구는
  미확인이다. 같은 원문을 다시 읽어도 기한을 늘리지 않으며 JS 소비자는 만료 시 경고를 제거한다.
- 이 결과는 운영 수집·신원·권한·양쪽 환경 인수나 새 플랫폼 SHA의 정책 허용을 뜻하지 않는다.
  기존 T28 CLI와 운영 allowlist는 수정하지 않았다.

검증할 checkout과 node를 준비하고 콘솔의 locked 개발 Python을 사용한다.
SHA는 해당 checkout의 검토한 40자리 값을 명시한다. 인자는 자격증명이 아니다.

```sh
python security/scripts/qualify_console_projection.py \
  --platform-root platform \
  --platform-revision "$PLATFORM_SHA" \
  --security-revision "$SECURITY_SHA"
```

출력은 합성 사례·코드 SHA·스크립트 hash와 `operational_acceptance=false`다.
서버 운영 토큰, kubeconfig, 외부 endpoint, 실제 데이터베이스는 필요하지 않다.

## 실제 조회와 미검증 사항

10:24 KST 읽기 전용 관측에서는 T10 Reader·등록 API·워크플로 호스트·창 수신기가 Ready였다.
새 T15 리허설 호스트는 `CrashLoopBackOff`로 0/1이었다. Reader v2 내용 해시는
Deployment·Pod 주석과 일치했다. 사용한 SSM 세션은 종료 상태까지 확인했다.
이 상태를 고치기 위한 patch·restart·exec는 수행하지 않았다.

UI의 실제 연결에는 운영자 세션·실제 계획, 인증된 생산자 등록·읽기 저장소,
기존 T10 권한 callback이 남아 있다. 격리 성공을 표시하려면 별도로 승인과 효과 원장,
해당 자원의 독립 거부 시험이 필요하다. 읽기 권한만으로 이 변경을 실행하지 않는다.
상세 순서는 [운영 연결 인계](../workload-operational-intake.md)를 따른다.
