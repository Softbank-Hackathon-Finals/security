# 두 설계 문서 연결의 로컬 검증 기록

## 검증한 변경

`security`와 `sova-test`의 `feature/security-modernization-integration` 작업본이다.
`sova-security` 버전은 0.10.0이며 로컬 wheel을 빌드했다. 기능별 Git 커밋과 작업 브랜치
배포 대상이다. 정식 패키지 릴리스·팀 `platform` 통합 및 운영 배포 완료를 뜻하지 않는다.

- 문서 원문의 SEC-PATCH-01~10, CTRL-01~09, POL-01~12, SG-1~3 추적.
- patch 19개 / migration 22개 필수 검사의 scope·revision·정확한 계획 digest 결속.
- 현재 등록·인가·보류 및 근거 서명·신뢰 철회 검증, 사전/사후 근거 분리.
- 기존 Sova 패치 실행기와 결합한 누락 차단·승인 철회·응답 유실 시험.
- 기존 계약을 변경하지 않는 새 JSON kind 두 개 및 오프라인 진단 CLI.
- 기존 원본 증거의 서명·최신 관측과 프로그램 연결, route/projection JSON kind 두 개.
- PostgreSQL 등록·철회·테넌트 격리, 새로운 FAIL과 동일 시각의 모호한 원본 차단.
- 실제 실행 후 증거 누락·변경 전 관측·검증 중 만료·신뢰 철회 시 보류 및 미재적용.
- 현재 platform 통제 schema의 명시적 선택과 원본 예제를 사용한 소비 시험.

## 실제 실행 결과

| 환경 / 명령 | 결과 |
|---|---|
| Ubuntu WSL, Python 3.12.16, PostgreSQL 17.11, OPA 1.22.0, security: `python -m pytest -q --tb=short --disable-warnings -ra` | **636 passed**, skip 없음 |
| 동일 환경 + 독립 목적지 PostgreSQL + 실제 TLS, sova-test: 동일 명령 | **1095 passed, 3 skipped**, 1 warning |
| Windows Python 3.12, security: `python -X utf8 -m pytest -q --tb=short --disable-warnings -rN` | **596 passed, 40 skipped** |
| Windows, Sova 새 CLI + 기존/새 패치 통합 테스트 | **28 passed** |
| security `ruff check src tests` / Sova `ruff check src tests demo` | 통과 |
| 빈 venv에 두 wheel을 `--no-index --no-deps`로 설치 | 통과 |
| 설치본에서 독립 계약 import, JSON 왕복, CLI catalog/example/check | 통과; 빈 근거는 UNKNOWN, 종료 코드 1 |
| CI와 같은 SHA-256으로 고정한 Gitleaks 8.30.1, 두 작업본 검사 | 유출 항목 없음, 값은 마스킹 |

Linux 검증은 현재 tracked 파일과 새 파일을 임시 디렉터리에 복사하고 Git의 원래
심볼릭 링크를 복원하여 실행했다. 시스템 Python이나 기존 DB를 변경하지 않았다.
uv 0.13.7로 임시 Python/venv를 만들고 현재 프로젝트의 선택 의존성을 설치했다.
이번 실행은 CI의 잠긴 전체 버전·Python 3.11/3.14 행렬을 재현한 결과가 아니다.

PostgreSQL은 공식 PGDG 키 지문을 확인한 패키지를 임시 경로에 압축 해제했고,
OPA는 저장소 CI의 공식 binary SHA-256을 검증했다. 테스트용 PostgreSQL 3개는
서로 다른 cluster_name/database/system_identifier를 사용한다. 소켓은 비공개 경로,
TCP는 loopback에만 열고 SCRAM을 요구한다. 복제 시험은 자체 테스트 CA로 서버 신원을
검증한 TLS 연결을 사용했다. 테스트 후 세 서버가 정지했음을 확인했다.

초기 PostgreSQL 14에서는 기존 복제 관찰기가 요구하는 카탈로그 컬럼이 없어 실패했다.
17로 맞춘 첫 확장 실행은 호스트 디스크 여유 부족 중 WSL I/O 오류가 발생해 무효 처리했다.
최종 DB 데이터는 메모리 임시 파일시스템에 두고 WAL 크기를 제한해 실행했다.
트랜잭션·RLS·복제·TLS 동작 시험이며 호스트 전원 장애 시 디스크 내구성 시험은 아니다.
상담 데이터 전환 시험은 writer에 종료 신호를 보내는 것과 실제 종료를 구분하도록,
`pg_terminate_backend`의 제한시간 있는 종료 확인을 사용하게 수정했다.

Windows 네이티브 Sova 전체 실행은 785 passed / 269 skipped / 20 failed / 17 errors였다.
원인은 기존 POSIX 전용 `geteuid`, `O_NOFOLLOW`, FIFO, Unix 권한 검사,
심볼릭 링크 checkout 및 OpenSSL 실행 환경이었다. 같은 작업본의 Linux 전체 실행에서
해소됐다. 이 변경으로 Sova의 Windows 전체 실행을 지원하게 된 것은 아니다.
Windows에서는 UTF-8 플래그도 필요하다. 플래그 없이 실행하면 기존 소스 경계 테스트의
기본 CP949 읽기에서 UnicodeDecodeError가 발생한다.

security 테스트의 Windows 호환성 수정은 두 가지다. 거대 입력 테스트에 짧은 pytest
ID를 부여해 Windows 환경변수 길이 제한을 피했고, 원래 POSIX만 지원하는 OPA 프로세스
테스트 5개는 Windows에서 명시적으로 skip한다. Linux에서는 5개 모두 실행·통과했다.

## 테스트가 증명하는 범위

서명 시험은 실제 Ed25519 연산을 사용한다. Sova 통합은 실제 SQLite effect 원장과
기존 승인·패치 검증기를 사용하며 외부 adapter 호출 횟수를 확인한다. 증거의 클라우드
측정값 및 verifier 등록 callback은 합성이다. 실제 공격 재현이나 실제 운영 통제
22개를 설치·검증한 결과로 해석하면 안 된다.

최종 Linux 실행에서는 실제 PostgreSQL·고정 OPA 시험을 모두 실행했다. 실제 논리 복제,
TLS publisher 관찰, 잘못된 CA 거부, 독립 DB 사이의 상담 데이터·세션·파일 검증 및
제한된 시험 경로의 전환·복구도 실행했다. 파일 데이터는 DB 복제와 별도로 다룬다.
단일 writer와 시험 앱 경계의 결과이며 임의 고객 앱의 무중단 이전 보증은 아니다.

남은 skip 3개는 다음과 같다.

- `test_consultation_container.py`: 명시적인 시험 컨테이너 이미지가 없음.
- `test_otel_collector_runtime.py`: 실제 Collector 실행 환경이 없음.
- `test_sqs_phase_delivery.py`: 소유 AWS SQS 등록이 없음.

AWS/RKE2·Harbor·WAF·SPIRE 등 실제 클라우드 보안 통제의 운영 인수는 수행하지 않았다.

## 산출물과 후속 인수

로컬 산출물은 `dist/sova_security-0.10.0-py3-none-any.whl`이며 Sova 소비자 wheel도
함께 빌드했다. `dist/local-build-manifest.json`과 `dist/SHA256SUMS`에 해시를 기록한다.
`dist/`와 검증 로그 `.local-notes/`는 Git에서 제외된다. 체크섬은 발행자 서명이 아니며
GitHub Actions가 발행한 릴리스 산출물도 아니다.

후속 platform 적용은 Sova의 `docs/platform-security-handoff.md`를 따른다.
현재 팀 계약별 실제 근거 생산자·저장소·신뢰 키·인증/인가·보류 조회를 연결하고,
AWS/RKE2에서 격리·거부·복원·컷오버·재스캔·회귀 시험을 수행해야 한다.
새 검사 프로필은 기존 T19 판정·사람 승인·실행 원장·실행 후 검증을 대체하지 않는다.
