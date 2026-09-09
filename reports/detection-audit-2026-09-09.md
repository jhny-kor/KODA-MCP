# MCP 취약점 탐지 정확성 점검 — 2026-09-09

**수정 전 감사 기록입니다. 후속 수정 및 최종 검증은 [보완 보고서](accuracy-fixes-2026-09-09.md)를 참조하세요.**

대상: security-mcp, HEAD `0503e06`. 운영 코드는 변경하지 않았다.

## 결론

오탐과 누락을 재현했다. 현재 도구는 제공된 텍스트에 대한 정적 휴리스틱 보조 검사이며, 결과 0건이나 `completed`가 보안상 안전함을 뜻하지 않는다. 아래 사례는 통계적 정확도 평가가 아닌 결함 재현이다. 실제 프로젝트 정답 데이터가 없어 전체 오탐률·미탐률을 수치로 산출할 수 없다.

## 재현된 문제

| 우선순위 | 문제 | 관찰 결과 | 근거 |
| --- | --- | --- | --- |
| 높음 | 서로 다른 함수의 변수 오염 상태 공유 | 전역 `x="echo fixed"`, 첫 함수의 지역 `x=request.args["cmd"]`, 두 번째 함수의 `subprocess.run(x, shell=True)`를 명령 주입 `confirmed`로 보고. 두 번째 함수는 고정된 전역 값을 사용하므로 제시된 외부 입력 흐름은 존재하지 않음 | `src/koda_core/checks/code_patterns.py:1701`의 파일 단위 taint 집합 및 1776의 승격 |
| 높음 | 규칙별 5건 제한을 숨김 | `eval(input())` 6줄 중 5줄만 반환하고 `findings_truncated=false` | `code_patterns.py:2332`, `secrets.py:105`; `_worker.py:216`은 이미 잘린 결과의 총 200건 제한만 인식 |
| 높음 | Kubernetes 주석에 따른 누락 | 같은 Pod 설정에서 `privileged: true`는 confirmed, `privileged: true # explanation`은 0건 | `src/koda_core/checks/configuration.py:312` 문자열 전체 일치. Compose에도 같은 패턴이 206에 존재 |
| 중간 | 파일명에 따른 검사 제외 | 동일 `eval(request.query.code)`가 `a.js`에서는 confirmed, `jquery-1.2.3.js`에서는 0건 | `code_patterns.py:2286` 이후 라이브러리 이름 판별과 조기 반환. 해당 파일 제외를 응답에서 식별하지 않음 |
| 중간 | 지원하지 않는 언어를 구체적으로 알리지 않음 | `a.svelte`의 `<script>eval(request.query.code)</script>`를 접수하고 completed/0건 반환 | `scan_service.py:280`은 금지 확장자만 거절; `code_patterns.py:2257`은 허용 언어만 검사. 일반 partial 안내만으로 어느 파일의 코드 검사가 빠졌는지 알 수 없음 |
| 중간 | 긴 한 줄이 파일 전체 검사를 생략시킴 | 2,000바이트 초과 주석 다음 줄의 `eval(request.query.code)`까지 0건 | `scan_service.py:295`, `_worker.py:203`. 이 경우 `generated_or_minified_files_not_evaluated` 경고는 정상 반환됨. 성능 보호 목적의 제한이나 일반 코드에도 적용됨 |

파일명/확장자/긴 줄 사례는 엔진이 의도적으로 범위를 줄인 결과다. 그중 긴 줄 제외만 구체적인 coverage gap으로 안내된다. 결과의 단순 0건 집계로는 이 차이가 사라진다.

추가 코드 검토: `code_patterns.py:1493` 이후 인증/속도 제한 후보 억제는 파일 전체에서 미들웨어 토큰을 찾는다. 해당 미들웨어가 각 라우트에 실제 적용되는지, 등록 순서와 범위를 검증하지 않는다. 라우트 단위 보호를 증명하는 조건으로 사용하기에는 불충분하다.

## LLM 전달 단계의 한계

- `_worker.py:143` 이후 `reason`에는 일반적인 `finding.description`만 들어간다. 코어의 구체적인 `verification_note`, `trace`는 응답 스키마에 전달되지 않는다. `confirmed`의 의미와 판단 근거가 LLM에 충분히 전달되지 않을 수 있다.
- `_worker.py:103`은 `start_line=end_line=finding.line`으로 반환한다. 여러 줄 호출이나 입력→위험 함수 흐름의 전체 범위를 보여주는 정보는 아니다.
- `server.py:372`의 설명은 부분 검사·결과별 출력·200건 제한 안내를 요구한다. 하지만 이 설명은 LLM의 실제 준수를 검증하는 장치가 아니다.
- 파일 선택은 클라이언트/LLM 책임이다. 서버는 개발자 작업 공간을 읽지 않아 누락 파일을 찾아낼 수 없다.
- 기본 기준은 `sw-dev-security-49`이고 `_worker.py:213`에서 기준에 매핑되지 않은 결과는 제외된다. `standard=all`도 모든 취약점을 탐지하는 뜻이 아니라 구현된 탐지 결과의 기준 필터를 해제하는 뜻이다.

## 폐쇄망에서 별도로 필요한 검사

현재 의존성 검사는 package.json, requirements, pyproject, Dockerfile의 고정 버전/HTTP/원격 셸 등의 패턴 검사다. `_worker.py:31`의 네 checker를 직접 실행하며, 잠금 파일의 전체 패키지 버전 해석이나 오프라인 CVE DB 대조 경로는 없다. 따라서 버전이 고정되어 있어도 알려진 CVE가 없는지 검증한 것은 아니다.

프로젝트 전체 호출 관계, 실제 인증·인가, 실행 환경, DAST, 정식 기준 충족 여부도 현재 검사 범위에 포함되지 않는다. 외부 통신이 차단되어 있다는 사실만으로 탐지 정확도가 확보되지는 않는다.

## 검증

- 기존 테스트: **53개 통과**. 프로젝트 선언 의존성을 uv 임시 환경에 준비해 실행했다. 폐쇄망 운영 환경 설치·실행을 검증한 결과는 아니다.
- 별도 MCP 서비스 재현: **8개 입력**을 실제 `scan_changed_files`와 자식 검사 프로세스로 실행. 모든 응답은 completed였으며 위의 오탐/누락이 관찰되었다.
- HTTP 인증부터 폐쇄망 LLM의 최종 자연어 보고서까지의 실제 통합 검사는 수행하지 않았다. 운영 모델·프롬프트·전달 파일 목록·실제 결과가 제공되지 않았다.
- 원시 재현 출력: `detection-audit-2026-09-09.jsonl`.
- 재현 실행 파일: `reproduce_detection_audit.py`. 테스트 데이터만 임시 디렉터리에서 처리하며 취약 코드 자체를 실행하지 않는다. 아래 명령은 저장소 루트에서 실행한다.

```sh
PYTHONPATH=src python3 reports/reproduce_detection_audit.py
PYTHONPATH=src python3 -m unittest discover -s tests -q
```

위 명령은 프로젝트의 선언 의존성이 설치된 Python 환경을 전제로 한다. 재현 스크립트는 관찰 결과를 출력하는 감사 도구이며, 수정 후 성공/실패를 판정하는 회귀 테스트는 아니다.

## 수정 우선순위

1. 함수 스코프를 구분해 잘못된 confirmed 승격을 막고, 위 사례를 회귀 테스트로 고정.
2. 규칙별 제한을 제거하거나 잘림 정보를 끝까지 전달. 미검사 파일과 이유도 응답에 포함.
3. 설정 문법을 인식해 주석 때문에 탐지가 달라지는 문제 보완.
4. 구체적인 판정 근거를 LLM에 전달하고, 미평가/후보/로컬 확인/실제 취약점 확정을 구분해 표시.
5. 별도 오프라인 의존성 취약점 검사 및 정답이 있는 실프로젝트 표본으로 탐지·보고 정확도 측정.

이번 변경은 감사 자료 3개 추가에 한정한다. 엔진 수정·배포·커밋은 수행하지 않았다.
