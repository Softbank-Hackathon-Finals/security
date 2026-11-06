# 사고 조사와 호환 가능한 보강

확인일 2026-11-06. 원문 두 제안서가 주 요구사항이며, 아래 조사는 추가 설계 근거다.
사고 발생일과 조사/제재/보고서 발행일을 구분한다. 기사나 공격자 주장을 측정 근거로 사용하지
않으며 피해 데이터·운영 비밀을 수집하지 않았다. 법규 준수 판정이 아니라 설계·시험 관점이다.

## 확인한 사례

| 사례 | 확인한 사실과 출처 | 이 프로젝트의 적용 판단 |
|---|---|---|
| Healthplex, 2021 사고·2025 제재 | 이전 이메일 환경의 MFA가 O365 외부 웹 접근 경로에서 완전히 작동하는지 확인하지 못했다. 감독기관은 이 경로의 MFA 누락과 과도한 메일 보관을 지적했다. [NYDFS 원문, 12~17항](https://www.dfs.ny.gov/industry-guidance/enforcement-discipline/ea20250814-healthplex) | CTRL-05/SEC-PATCH-08: 기존 환경 PASS를 목적지에 복사하지 않는다. 웹·API·workload처럼 실제 접근 경로별 증거를 등록하고 목적지에서 다시 시험한다. 모든 환경의 MFA를 우리 서비스 토큰으로 대체하지 않는다. |
| PayPal, 2022 변경·2025 합의·2026 보고서 | 데이터 수집 흐름 변경 후 민감정보가 마스킹되지 않은 채 노출됐고, 규정된 변경 절차가 지켜지지 않았다고 NYDFS가 정리했다. credential stuffing으로 해당 정보에 접근한 것으로 설명한다. [NYDFS 2025 연차보고서, 인쇄면 4](https://www.dfs.ny.gov/system/files/documents/2026/04/Consumer-Protection-and-Financial-Fraud-Enforcement-Annual-Report-for-2025.pdf) | SEC-PATCH-05·06/CTRL-05: 승인된 정확한 계획을 실행 직전에 다시 확인한다. 적용 후 기능 정상뿐 아니라 실제 민감정보 노출·인가 거부 결과도 필요하다. 사전 검사 결과로 사후 완료 처리하지 않는다. |
| Bayview 계열, 2021 침해·2025 합의 | 같은 감독기관 보고서는 패치 관리, 취약점 개선 감독, 자산 추적의 부족을 기여 요인으로 들었다. [NYDFS 보고서, 인쇄면 3~4](https://www.dfs.ny.gov/system/files/documents/2026/04/Consumer-Protection-and-Financial-Fraud-Enforcement-Annual-Report-for-2025.pdf) | SEC-PATCH-01·02·09: 스캔·수집 실패를 취약점 없음으로 표시하지 않는다. 마지막 실제 성공 시각을 보존하고 오래된 관측을 재수집해 유효기간을 늘리지 않는다. |
| RORZE 대만 자회사, 2025 발표 | 회사는 VPN 접근 이후 가상화 기반 서버에서 랜섬웨어가 실행됐다고 설명했다. 정보 유출 여부는 확인할 수 없었다고 밝혔다. 파산 사례로 발표한 자료는 아니다. [회사 공식 후속 공지, 2025-05-20](https://www.rorze.com/en/news/2025/05/20/2562/) | SG-1/CTRL-01·06: 한 서비스 자격 침해가 다른 tenant의 읽기/쓰기 또는 백업 삭제 권한으로 번지지 않도록 계정과 네트워크를 분리한다. UNKNOWN을 유출 없음으로 바꾸지 않는다. |
| KNP Logistics, 2023 사고·사업 종료에 대한 회고 | 전 임원의 발표를 정리한 행사 주최기관은 백업도 피해를 입었고 재무 보고 시스템 복구 실패가 사업 지속에 치명적이었다고 전한다. 이는 영국 사례다. [EMCSC 발표 정리](https://www.emcsc.co.uk/article/inside-cyber-security-anatomy-of-a-ransomware-attack) | SG-3/CTRL-06: 복구 자산 보유와 실제 업무 복원 성공을 분리한다. DB 연결만으로 복구를 완료 처리하지 않고 T12/T13/T20/T35의 데이터·업무 검증에 연결한다. |

대만 ACS의 2026-07-27 공식 안내는 백업·업데이트·계정 보호와 사고 후 격리·증거 보존·
깨끗한 복원을 강조한다. 이 자료도 특정 대만 회사의 파산을 입증하지 않는다.
[ACS 공식 자료](https://web.moda.gov.tw/ACS/press/news/press/20242).

## 아직 확정하지 않은 사용자 언급

`니케`가 Nike인지 Nikkei인지 이 대화만으로 확정하지 않는다. Nikkei로 보이는 2026년 10월
사건의 [회사 공지 주소](https://www.nikkei.co.jp/nikkeiinfo/news/information/1561.html)는 찾았지만
웹 도구와 직접 읽기에서 본문을 얻지 못했다. 재인용된 건수·원인·피해 범위를 검증된 사실로
채택하지 않았다. Nike 관련 보도도 동일 사건으로 합치지 않았다.

추가 확인한 [NIKE 2026 10-K, Item 1C](https://investors.nike.com/sec-filings/all-sec-filings/content/0000320187-26-000088/nke-20260531.htm)는
과거 사고 경험과 해당 공시 시점까지의 사업·영업실적 중대 영향 부재를 함께 서술한다.
이 공시는 2026년 1월 특정 유출 주장·규모·원인을 확인하는 자료로 사용하지 않는다.
독립 시험, 취약점 관리, 외부 연동 위험 평가를 운영하는 것과 특정 통제의 실제 성공을 구분한다.

`보안을 우선시하지 않은 대만 회사의 파산`은 회사명과 1차 근거를 특정하지 못했다.
다른 나라의 KNP/23andMe/Einhaus 사례로 바꾸거나 보안 소홀을 단독 파산 원인으로 단정하지
않는다. 정확한 사례명이 확보되기 전까지 그 주장만 보류하며 구현 작업은 계속한다.

## 구현·시험에 반영한 항목

1. **자격 침해의 읽기 범위 제한**: 테넌트 전용 SELECT 역할과 restrictive RLS를 추가했다.
   직접 SQL로 tenant GUC를 바꿔도 타 tenant 자료는 보이지 않는다. 정책·권한 drift는 판정을 막는다.
   기존 shared credential RLS의 한계를 명시한 ADR-0002와 실제 PostgreSQL 시험이 있다.
2. **원본 관측 시각 보존**: T33 변환기의 유효기간을 원본 event/last_success에도 결속했다.
   남은 유효기간 1초인 관측을 다시 받아도 1초만 유효하다. 기한을 넘긴 heartbeat는
   coverage-unavailable이며 오래된 finding은 거부한다. wire schema와 플랫폼 코드는 바꾸지 않는다.
3. **실행 직전·직후 경계 유지**: 현재 승인/등록/철회·단일 접수를 실제 T10 모듈과 대조했고,
   Sova 효과 적용 후 서비스 장애에서는 APPLIED와 hold를 유지하며 다시 적용하지 않는다.
4. **서비스 장애 전파 제한**: 입력/응답·worker·시간·DB 읽기·로컬 감사 크기를 제한한다.
   감사 상한에 도달하면 기록을 덮지 않고 새 판정을 보류한다. 앱은 이 서비스의 가용성에
   직접 의존하지 않도록 배포 경계를 둔다.

## 실제 환경에서 이어갈 검증

외부 웹 접근에서 MFA/세션·CSRF·CSP 검증, T7 audience/철회 실측, 서비스 역할로 Secret 읽기·
Pod exec·배포·DB 쓰기 거부, 다른 namespace/tenant 접근 거부, T24 원문 수집·보존 확인,
변경 이후 실제 복원·업무 정합성은 등록된 팀 환경과 담당 공급자가 필요하다. 개인 환경의
합성 PASS로 채우지 않는다. 기존 22개 검사와 해당 경로의 `ProgramEvidenceRoute`에
원본 증거를 연결하며 새 실행 엔진·모델 승인·자동 보류 해제 기능을 만들지 않는다.

## 추가 조사: 연동 토큰의 수평 확산

2025-08 Salesloft Drift 사고의 [Google 조사팀 원문](https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift)은
탈취한 OAuth 토큰으로 연결된 Salesforce 자료를 읽고, 그 자료에서 다른 자격을 찾은 행동을
설명한다. 08-28 갱신은 다른 연동도 조사·철회 대상으로 확장했다. 핵심 서비스 자체가 침해된
것과 고객이 승인한 연동 자격이 악용된 것을 구분한다.

이 프로젝트에서는 서비스 자격의 사용 범위를 최소화한다. [ADR-0008](adr/0008-service-token-use-boundaries.md)에
단일 audience·원래 수명 600초 제한을 구현하고, 실제 Kubernetes가 인증한 더 넓은 토큰도
서비스가 거부하는 시험을 추가했다. 기존 토큰 생성기와 실행 권한을 합치지 않는다.
2026-09 [NIST IR 8587](https://csrc.nist.gov/pubs/ir/8587/final)의 workload/audience 지침도
참고했지만 이 변경을 NIST 전체 준수나 탈취 토큰 재사용의 완전한 방지로 표현하지 않는다.
