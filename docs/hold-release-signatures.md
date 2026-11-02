# 보안 보류 해제의 승인 서명

보안 보류 해제는 일반 배포 승인과 별도 권한이다. 패치 성공이나 정상 헬스체크만으로 보류를 해제하지 않는다. `SecurityHoldService`는 독립 승인, 현재 revision, 사고 이후 재검증 근거와 저장소 CAS를 확인한다.

## 두 종류의 근거

| 근거 | 내용 | 인증 경로 |
| --- | --- | --- |
| 해제 승인 | HoldRelease 전체 문서: 사고 ID·scope·revision·예상 hold revision·요청자·승인자·사유·재검증 ID와 digest·시각·기한 | `HoldReleaseAuthority` |
| 보안 재검증 | 사고 이후의 `security-release:<hold ID>` 결과, `security-revalidation-v1`, 정확한 scope·revision·기한 | 기존 `SignedEvidenceAuthority` |

`hold_release_record(request, evidence_id=...)`는 해제 승인 전체를 정규화하고 SHA-256으로 묶은 EvidenceRecord를 만든다. `sova.security.hold-release-approval.v1`은 재검증 verifier version과 다르다. 원래 EvidenceEnvelope·Ed25519·검증기 등록 저장소를 재사용하며 별도 승인 원장을 만들지 않는다.

## 호스트 연결

1. 인증된 보안 승인자가 정확한 해제 요청을 검토한다.
2. 승인 서비스는 그 승인자의 등록된 issuer로 승인 record를 서명하고 기존 envelope 저장소에 보관한다.
3. `HoldReleaseAuthority`에 envelope 조회, 현재 revision, 현재 key registry, 승인자 권한 조회와 시계를 주입한다.
4. 이 authority를 `SecurityHoldService.authenticate_release`에 연결한다. 재검증 서명은 별도 authority에 연결한다.
5. 서비스는 CAS 직전 두 권한과 서명·기한·현재 hold 상태를 다시 확인한다.
6. 저장 후 정확한 해제 결과를 재조회해 확인한다. 불확실하면 성공을 반환하지 않으며 자동 재시도하지 않는다.

Authority는 envelope의 issuer가 요청의 `approved_by`와 같은지 확인한다. 입력이 같더라도 키 철회·역할 변경·권한 회수·revision 변경·envelope 교체·만료를 거부한다. 요청자와 승인자는 다르고, 사고를 제기한 사람은 해제를 승인할 수 없다. 재검증 결과·hold ID·사유·범위 하나라도 바뀌면 기존 승인 서명을 사용할 수 없다.

## 신뢰 경계

이 서명은 로그인·MFA·실제 사람의 참석을 증명하지 않는다. 호스트가 인증된 사용자와 승인 issuer의 관계, 키 발급·회전·철회, 승인자와 독립 검증기의 역할 분리 정책을 관리해야 한다. 에이전트·브라우저·실행 샌드박스에는 승인 키를 제공하지 않는다. 키 registry에 무제한 등록 권한을 부여하면 이 경계를 유지할 수 없다.

애플리케이션 재확인과 DB CAS는 분산된 권한 시스템 전체에 대한 단일 원자 트랜잭션이 아니다. 권한 철회와 운영 명령을 엄밀하게 직렬화해야 하는 호스트는 동일 실행권·fencing 또는 거래 경계에 연결해야 한다. 이 패키지 시험을 기업 인증 통합 완료로 표현하지 않는다.

저장 응답 또는 readback이 불명확하면 쓰기가 실제로 완료됐을 수도 있다. 운영자는 현재 hold 상태를 조회하고 확인한 뒤 처리한다. 임의의 새 사고를 만들거나 기존 해제를 반복해 성공으로 포장하지 않는다.

## 검증

실제 Ed25519와 격리 PostgreSQL에서 두 서명의 저장·조회·정상 해제, 재검증 조회 중 승인 키 철회 시 원래 보류 유지, 저장 응답/readback 실패의 성공 표시 차단을 시험한다. 합성 사고·재검증 데이터이며 실제 침해 대응이나 외부 IdP 연동 시험은 아니다.
