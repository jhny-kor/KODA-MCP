# KODA Security Advisory MCP

폐쇄망에서 Continue 또는 선택적으로 Open WebUI가 호출하는 비차단 보안 자문 MCP입니다.

이 서버는 클라이언트가 직접 전송한 변경·생성 텍스트 파일만 요청별 자식 프로세스에서 검사합니다. 개발자 PC 경로, Git diff, 저장소 전체, 런타임, OSV·Grype·SBOM, DAST, 인터넷, 형식적 준수 여부를 읽거나 판정하지 않습니다. 결과는 부분 자문이며 전체 프로젝트·런타임·형식적 준수를 평가하지 않습니다.

## 로컬 확인

연결망 Python 환경에 고정 의존성을 설치한 뒤 실행합니다.

```bash
python3 scripts/verify_source.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m compileall -q src
```

운영 이미지는 `mcp==2.0.0`, Python 3.12 Linux amd64 wheelhouse로 오프라인 빌드합니다. 설정 파일에는 raw token이 아니라 SHA-256 digest만 넣고, 설정 파일은 실행 UID가 소유한 mode `0400` regular file이어야 합니다.

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
printf '%s' '<raw-token>' | sha256sum
chmod 0400 /run/secrets/koda_mcp.json
docker compose -f deploy/compose.yaml config --quiet
```

MCP 엔드포인트는 `https://<KODA_FQDN>/mcp`이며 Continue용 token과 Open WebUI용 token을 분리합니다. TLS 검증을 끄거나 query token을 사용하지 않습니다. `/healthz`는 컨테이너 내부 확인용이고 Nginx에서 외부로 공개하지 않습니다.

응답의 `completed/partial`은 안전·준수 판정이 아니며, finding이 없을 때도 제공된 파일에서 발견사항이 관찰되지 않았다는 의미만 가집니다. 실패·busy·timeout은 작업을 차단하지 않는 `not_evaluated` 상태입니다.

별도 기준을 지정하지 않으면 두 도구 모두 `sw-dev-security-49`를 기준으로 점검하며, KODA 자체 기준은 사용하지 않습니다. 명시적으로 선택할 수 있는 기준은 `cwe-top-25-2025`, `owasp-top-10-2025`, `owasp-asvs-5`, `owasp-proactive-controls`, `sw-dev-security-7-types`, `kisa-secure-coding-guide`입니다. 응답의 `selected_standard`가 실제 적용 기준이고, 해당 기준에 매핑되지 않은 규칙은 finding에서 제외됩니다.

각 guidance item과 finding의 `criteria`에는 감사된 표준 매핑의 기준 ID·항목명·분류·CWE가 포함됩니다. `direct_control`은 탐지 규칙에 직접 연결된 소프트웨어 개발보안 49 항목이고, `related_category`는 CWE·OWASP·KISA의 관련 범주입니다. `standard_references`에는 판본·발행기관·원문 URL이 있으며, `criteria_truncated=true`이면 응답 크기 제한 때문에 관련 범주 일부가 생략된 것입니다. 이 매핑은 설명 근거이지 형식적 위반·준수 판정이 아닙니다.

## Continue 기본 구성

다음 값을 조직의 실제 내부 FQDN, CA 경로, 모델 ID로 교체합니다. KODA token과 모델 API key는 workspace 파일에 직접 쓰지 않고 조직이 선택한 `.env` 또는 Continue secret 저장소에서 주입합니다.

```yaml
name: Internal coding agent with KODA
version: 0.1.0
schema: v1

models:
  - name: Internal coding model
    provider: openai
    model: <OPEN_WEBUI_MODEL_ID>
    apiBase: https://<OPEN_WEBUI_FQDN>/api
    apiKey: ${{ secrets.OPEN_WEBUI_API_KEY }}
    capabilities:
      - tool_use
    roles:
      - chat
      - edit
      - apply

rules:
  - |
      KODA는 비차단 보안 자문 도구다.
      사용자가 다른 기준을 명시하지 않으면 standard는 sw-dev-security-49를 사용한다.
      실행 보안에 영향을 주는 작업 전에는 koda_get_security_guidance 호출을 시도한다.
      변경이 끝나면 직접 변경하거나 생성한 텍스트 파일의 전체 내용만
      koda_scan_changed_files에 한 번 전달한다.
      Git diff, 저장소 전체, 삭제 파일, 바이너리, archive는 보내지 않는다.
      finding을 이유로 자동 수정하지 않으며 사용자가 수정 요청한 경우에만 한 번 재검사한다.
      KODA 실패는 저장, 완료, Git 작업을 차단하지 않는다.
      completed/partial을 PASS 또는 안전·준수로 표현하지 않는다.
      finding을 설명할 때 selected_standard, 경로·줄·rule_id 다음에 적용 기준의 criterion_id·항목명을 우선 제시하고,
      관련 CWE·OWASP·ASVS related_category와 권고조치를 함께 설명한다.
      related_category를 직접 위반으로 단정하지 않고 mapping_notice와 coverage_gaps를 반드시 반영한다.
      최종 응답에는 아래 상태 중 하나를 정확히 한 줄 포함한다:
      KODA: completed/partial — <N> findings in provided files
      KODA: completed/partial — no findings observed in provided files
      KODA: rejected/not_evaluated — <error_code>
      KODA: busy/not_evaluated
      KODA: timed_out/not_evaluated
      KODA: failed/not_evaluated
      KODA: not_requested

mcpServers:
  - name: KODA
    type: streamable-http
    url: https://<KODA_FQDN>/mcp
    requestOptions:
      caBundlePath: <ABSOLUTE_INTERNAL_CA_PATH>
      headers:
        Authorization: Bearer ${{ secrets.KODA_MCP_TOKEN }}
```

실제 완료 판정에는 Continue에서 두 도구 호출, finding 존재·0개 fixture, KODA 중단 fallback, non-Git workspace를 각각 확인해야 합니다. 실제 FQDN·CA·token·tool-calling 모델이 제공되지 않은 환경에서는 이 항목을 `UNVERIFIED`로 기록합니다.

## 원본과 라이선스

복사된 KODA core 파일과 원본 `standards.py`에서 생성한 축약 매핑의 원본 커밋·경로·SHA-256은 [SOURCE_PROVENANCE.json](SOURCE_PROVENANCE.json)에 고정했습니다. 원본의 Apache-2.0 `LICENSE`와 `NOTICE`를 유지하며, 실행 의존성 고지는 [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt)에 있습니다.
