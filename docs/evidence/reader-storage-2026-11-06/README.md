# SELECT reader의 임시 테이블·대형 객체 생성: 수정 전후

2026-11-06 14:58 UTC, 본인 소유의 격리 PostgreSQL 17.11과 Python 3.14.10에서 실행했다.
기존 DB/프로세스는 사용하지 않았다. private Unix socket만 열고 TCP는 닫았다.
테스트가 확인하는 cluster_name/DB는 `sova-security-test` / `sova_security_test`다.

| source | 명령 결과 | 의미 |
|---|---|---|
| `a399357a1e8c9a553df22abaa1974319775fa2c8` | **4 FAIL, 0.35초** | 기존 runtime 검사를 통과한 SELECT reader가 TEMP 및 세 대형 객체 생성에서 모두 `DID NOT RAISE InsufficientPrivilege` |
| `5ddf281b31568e49cdd1a2c993e8d8172cdc7b1e` | **12 PASS, 0.66초** | 전용 DB 준비 후 실제 생성 거부 4개, 직접/PUBLIC 재부여 시 runtime 거부 8개 |

두 source의 `src`, `pyproject.toml`, 관련 tests/conftest를 `git archive`로 별도 임시 경로에
추출했다. 각 source의 `src`를 PYTHONPATH로 지정했으며 패키지 설치를 바꾸지 않았다.
각각 다음 명령을 실행했다. `--runxfail`은 이전 source의 예상 실패 표기를 무시하여
실제 실패 지점이 보이도록 한다. 기대 실패가 환경 설정 오류였던 것은 아니다.

```text
python -m pytest -q --runxfail --tb=short tests/integration/test_review_reader_storage.py
```

관리자 DSN은 본인 격리 DB의 `SOVA_SECURITY_TEST_POSTGRES_DSN`에만 제공한다.
일반 공유/운영 DB에서는 실행하지 않는다. 각 시험은 작은 객체 한 개를 rollback하고
자기 역할을 정리한다. 전체 종료 뒤 본인 PG의 `postmaster.pid`가 없음을 확인했다.
전용 DB 준비의 PUBLIC 변경은 fixture가 원래 상태로 복구한다.

- [수정 전 traceback](before.txt), [수정 후 출력](after.txt), [결과](result.json)
- before SHA-256: `6e86485924403c85cb56493cb12b9841a1fcdf0f4b6f6e0f48d9f1f13f941ba1`
- after SHA-256: `5af02ab3ce1a4a1e85f4e75799d1fddbdf29350ca4034adfd7a4df3ecbb835f3`
- result SHA-256: `9c8519e1f44840e9aaacf061558b925f18a7e9f1815b691a07463d531f6b0ba5`

실제 PG18.4 전체 CI 결과는 별도로 기록한다.
이 시험은 자원 고갈 부하, 운영 CNPG/HBA/CNI, 관리자 침해나 모든 DB 가용성을 검증하지 않는다.
운영 연결 조건은 [ADR-0019](../../adr/0019-reader-storage-creation-boundaries.md)를 따른다.
