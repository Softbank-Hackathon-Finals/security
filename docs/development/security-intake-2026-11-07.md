# T14·T33 맥 인수 준비와 개인 어댑터 보강

- 시작: 2026-11-07 05:27 KST. 사용자 요청 기한: 같은 날 07:00 KST.
- 플랫폼 기준: `c364e6284d2e635ff86001e2feac88560ed23ebc` detached 읽기 사본.
- 변경 위치: 개인 `security`, `sova-test`. 공용 플랫폼 코드·운영 자원은 변경하지 않는다.
- 요구: 기존 T14/T33/T19 계약 소비, 두 보안 문서의 identity-boundary,
  continuous-revalidation, protection-parity, audit-trail 및 인수 근거 보존.

## 발견과 결정

1. 기존 detection bridge는 T33의 예전 schema만 고정했다. 최신 normalizer v2의
   필수 version과 INGESTION_GAP을 거부하는 차이를 확인했다. 기존 등록은 보존하고
   등록의 schema digest로 최신 고정본을 선택한다. 수집기를 새로 복제하지 않는다.
2. T33의 표시 마스킹은 원본 계정·자원 소유권 증명이 아니다. 마스킹된 값을 등록에
   넣어 통과시키는 경로를 거부한다. 실제 AWS/GCP mapping은 후속 실환경 인수 항목이다.
3. 느린 인증 콜백 중 등록 철회·만료가 생기면 기존 admission이 보류를 먼저 생성하고
   뒤에서 거부하는 문제를 회귀 시험 2개로 재현했다. 인증 뒤 현재 등록·시각·권한을
   재검사한다. 별도 저장소의 모든 효과를 원자적으로 만든다는 주장은 하지 않는다.

## 로컬 검증

- Windows Python 3.12.1: detection 기존·최신 계약 및 admission 회귀 47 PASS.
- 수정 전 느린 인증 회귀 2 FAIL → 수정 후 2 PASS. 실행은 모의 인증·메모리 저장소다.
- 최신 platform 실제 T33 normalizer를 호출하는 온프렘 2건과 AWS 마스킹 거부 교차 시험.
- 최신 T10/T19 소비 시험은 Windows에서 POSIX 조건에 의한 skip이 있어 Linux CI로
  보완한다. CI의 실제 SHA·결과는 완료 후 추가하며 지금 통과로 간주하지 않는다.

## 남은 실환경 인수

AWS 양성 탐지와 실제 scoped mapping, SCC 프로젝트·인증, 온프렘 Kyverno/Falco 설치·전송,
T14 양쪽 full 시험 원문, T19 원문 인증·저장·소비, T34 감사·T35 복구는 이 로컬 시험으로
완료되지 않는다. `bravo-personal`만 사용하며 공용 환경 조회 시점과 변경 시험 창은
맥에서 기존 담당 절차로 확인한다. 이번 작업은 클라우드 로그인·호출을 수행하지 않는다.
