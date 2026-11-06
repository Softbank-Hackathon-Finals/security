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
- 최초 최신 T10/T19 소비 시험은 18 PASS·19 SKIP였다. 후속 확인에서 19 SKIP는
  OS 조건이 아니라 네 개 시험 파일의 feature별 baseline 목록 누락이었다. 해당 목록에
  c364e628을 명시적으로 추가해 현재 key·서명·workflow·재평가 시험도 실제 실행한다.
  CI의 최종 SHA·결과는 완료 후 추가하며 중간 실행을 최종 통과로 간주하지 않는다.

## 남은 실환경 인수

AWS 양성 탐지와 실제 scoped mapping, SCC 프로젝트·인증, 온프렘 Kyverno/Falco 설치·전송,
T14 양쪽 full 시험 원문, T19 원문 인증·저장·소비, T34 감사·T35 복구는 이 로컬 시험으로
완료되지 않는다. `bravo-personal`만 사용하며 공용 환경 조회 시점과 변경 시험 창은
맥에서 기존 담당 절차로 확인한다. 이번 작업은 클라우드 로그인·호출을 수행하지 않는다.

## 인수 목록 도구와 추가 검증

`application.acceptance_intake.intake_plan`은 T5 profiles 원본 바이트와 schema를 고정해
20개 full 시험 목록을 생성한다. T14 ControlRun과 T33 SourceStatus는 스키마·중복·시각을
검사한 뒤 원문 hash와 보고된 상태만 투영한다. source/target 혼합, 빈 결과, 만료된
PASS, INGESTION_GAP, 민감 발췌 제거를 시험했다(14 PASS). 실제 원문 인증·계획 결속을
하지 않으므로 모든 결과는 LIVE_NOT_VERIFIED이며 실행 권한은 항상 false다.

Sova의 `security-intake-plan`은 같은 함수를 호출하며 기존 Mac/Linux 개인 파일 검사를
재사용한다. 클라우드·shell subprocess가 호출되지 않는 소비 시험을 포함한다.
버전은 0.11.1로 올려 이전 검증 wheel과 구분한다. 과거 0.11.0 이미지 검증은 그대로 보존한다.

Windows 전체 unit/contract 회귀에서 942 PASS·47 SKIP와 기존 UTF-8 기본 인코딩 실패
1개를 관측했다. 해당 계약 시험을 UTF-8 모드로 다시 실행해 3 PASS를 확인했다.
플랫폼 T33 회귀도 Windows에서는 UTF-8 설정 뒤 POSIX O_NOFOLLOW 조건에서 실패하므로,
현재 platform 코드는 바꾸지 않고 Linux CI에서 정본 회귀 전체를 실행한다.

최종 보강으로 T10 서버 발급 workload ID를 카탈로그 표시 이름으로 강제하지 않고,
양쪽 workload 일치·서로 다른 환경/run ID를 확인한다. 인증 중 보류 권한만 철회되는
경우도 효과 직전에 다시 검사한다. 최종 detection/intake 회귀는 64 PASS다.

feature별 baseline 목록을 보완한 후 최신 c364e628의 실제 T10/T19·T33 교차 시험은
**37 PASS / 0 SKIP (20.84초)**다. 이 실행은 실제 플랫폼 코드·SQLite와 합성 측정/신원을
사용한다. 실제 클러스터 로그인·수집·인가 인수를 증명하지 않는다.
