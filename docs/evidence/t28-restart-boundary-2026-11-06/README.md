# T28 운영자 회차 기록의 중단·재시작 경계

2026-11-06, 플랫폼 `98885a69999398bfe3f49fbc8324a7b19aae3e16`의 `scripts/happy_path.py`를
읽어 모의 operator 하나로 대체했다. **실제 operator 명령·클라우드·DB 변경은 0회**다.
Python 3.14에서 실행했고 [원본 결과](result.json)에 source SHA-256을 보존한다.

## 관찰

operator가 메모리 효과를 만든 직후, 결과 줄을 append하기 전에 프로세스 중단과 같은
BaseException을 주입했다. 실제 프로세스를 강제 종료한 시험은 아니다. 첫 실행 뒤 파일에는
header 한 줄만 있었다. 같은 기록으로 다시 실행하면 이전 효과를 모른 채 operator를 다시 호출해
메모리 효과가 **1회에서 2회**가 됐고 종료 코드는 0이었다.

현재 스크립트는 기록된 UNKNOWN/FAILED는 재실행하지 않는다. 그러나 명령 시작 전의 영속 접수 기록이
없어 위 창의 중단을 기록된 UNKNOWN과 같게 취급할 수 없다. 실제 하위 도구 자체의 멱등성이 영향을
줄 수 있지만, 이 시험은 모든 하위 도구가 안전하다고 입증하지 않는다. 일반적인 단일 실행 보장이나
보안 변경 집행의 정본으로는 **BLOCK**이다. 플랫폼 T10 원장 자체의 결함으로 확대하지 않는다.

## 인계 방향

새 JSONL 승인/실행기를 만들지 않고 기존 T10/T31의 영속 접수·단일 claim·원장 조회를 재사용한다.
operator가 반드시 별도여야 하는 경로는 현재 계획/diff/image/application_id에 결속된 시작 기록을
효과 전에 영속화하고, 미완료 접수는 readback/조정 전까지 재실행하지 않아야 한다. `confirm` 문자열은
현재 승인 검증을 대체하지 않는다. JSONL은 회차 설명용 자료로 유지한다.

Sova는 이미 `EffectExecutor`의 IN_FLIGHT 기록과 재접수 거부, PostgreSQL 소유권/별도 복구를 사용한다.
`test_restart_does_not_reissue_an_inflight_effect`와 실제 child `os._exit(44)`를 사용하는
`test_real_worker_exit_blocks_takeover_until_verified_recovery`가 해당 범위를 검증한다.
후자는 앞선 전체 Sova 로컬 회귀에 포함됐으며 이 T28 probe가 그 시험을 다시 수행한 것은 아니다.

## 재현

```sh
python3.14 docs/evidence/t28-restart-boundary-2026-11-06/reproduce.py --platform /absolute/clean/pinned-platform
```

스크립트는 정확한 SHA·clean checkout을 먼저 확인하고 Git 객체에서 원문을 읽는다. 운영 단계 전체를
모의 단계로 바꾼 뒤 메모리 callback만 호출한다. 출력 BLOCK은 예상한 문제 재현이며 서비스 배포 판정과
별개다. 최초 실행은 기본 Python 3.10의 UTC import에서 중단돼 실측으로 세지 않았고, 위 3.14 재실행만 기록했다.
