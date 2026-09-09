# 폐쇄망 Docker 번들 배포

이 문서는 연결망 빌드 PC에서 만든 KODA MCP `tar.gz`를 승인된 매체로 폐쇄망 Docker 호스트에 옮겨 설치하는 절차입니다. 이 저장소를 폐쇄망에서 clone하거나 `docker build`, 이미지 registry 접근, `docker compose pull`을 하지 않습니다.

## 0. 배포 조건과 범위

현재 번들의 **운영 대상은 Linux amd64 / Python 3.12**입니다. 연결망 빌드 PC는 macOS arm64여도 되지만 Docker가 amd64 이미지를 cross-build 또는 emulation으로 만들 수 있어야 합니다. 폐쇄망 Docker 호스트의 아키텍처는 amd64인지 확인합니다.

```bash
uname -m                    # 빌드 PC는 arm64 또는 x86_64 가능
docker version
docker info --format '{{.OSType}}/{{.Architecture}}'  # 배포 호스트에서 linux/amd64 여야 함
docker compose version
```

arm64 호스트에는 이 번들을 설치하지 않습니다. arm64용 lock, wheelhouse, 베이스 이미지와 별도 검증을 준비한 뒤 번들 생성 스크립트의 amd64 고정을 함께 변경해야 합니다. 빌드 PC가 arm64인 경우에도 `scripts/build_airgap.sh`가 지정하는 `--platform linux/amd64`의 실제 이미지 검사를 통과해야 합니다.

폐쇄망 설치가 검증하는 것은 이미지 적재, compose 설정, 컨테이너 기동과 KODA의 로컬 health endpoint입니다. MCP 클라이언트 연결, 내부 CA/FQDN, 토큰 인증, 실제 LLM tool call은 별도의 운영 확인 단계입니다. CVE/OSV, 저장소 전체, Git diff, 런타임·DAST 검사는 이 서비스의 범위가 아닙니다.

## 1. 연결망에서 번들 생성

연결망 빌드 PC에서 `WHEELHOUSE_DIR`에 Linux amd64/Python 3.12 wheel만 준비하고 다음을 실행합니다. wheel은 lock 파일의 해시와 대조하며 받습니다.

```bash
pip download --require-hashes -r requirements-linux-amd64-py312.lock \
  --dest wheelhouse --only-binary=:all: \
  --platform manylinux2014_x86_64 --platform any \
  --python-version 3.12 --implementation cp
```

`pip download`는 lock에 기록된 해시와 맞는 바이너리 wheel만 받아야 합니다. wheelhouse와 번들에는 raw token, token digest, TLS private key를 넣지 않습니다. 빌드 PC에는 Docker BuildKit과 `syft` 또는 `docker sbom`도 필요합니다.

빌드와 검증은 아래 한 경로를 사용합니다. 태그는 릴리스마다 바꾸고 폐쇄망에서도 같은 값을 사용합니다. 번들 파일명은 스크립트에서 고정하므로 출력 디렉터리를 릴리스별로 분리합니다. 저장소 루트에서 실행합니다.

```bash
export KODA_MCP_IMAGE=koda-mcp-security:accuracy-20260909
release_dir="$PWD/dist/accuracy-20260909"
WHEELHOUSE_DIR="$PWD/wheelhouse" scripts/build_airgap.sh "$release_dir"
scripts/verify_airgap.sh "$release_dir/koda-mcp-security-0.1.0-linux-amd64.tar.gz"
(cd "$release_dir" && sha256sum koda-mcp-security-0.1.0-linux-amd64.tar.gz \
  > koda-mcp-security-0.1.0-linux-amd64.tar.gz.sha256)
```

스크립트는 빌드 단계의 네트워크를 차단하고 이미지 tar, Compose/Nginx 예시, 예시 설정, lock·wheel 해시, SBOM, 라이선스 고지와 전체 파일의 `SHA256SUMS`를 묶습니다. 베이스 이미지 취득과 wheel 다운로드는 연결망에서 먼저 완료해야 합니다. `verify_airgap.sh`는 해시·이미지 메타데이터·Compose 구성을 검사하고 내부 Docker 네트워크에서 외부 TCP/DNS 차단을 확인합니다. 실제 MCP 요청 검증은 아래 운영 확인 단계에서 수행합니다.

Mac에서 `sha256sum`, GNU `sort`/`xargs` 등 스크립트의 도구가 없으면 이를 준비한 연결망 Linux 빌드 환경을 사용합니다. 생성된 tar.gz는 소스 저장소에 커밋하지 않습니다. 압축 파일 해시는 승인된 별도 전달 경로의 값과도 대조해야 하며, 파일 옆의 해시만으로 출처가 인증되지는 않습니다.

## 2. 매체 이송과 폐쇄망 적재

승인된 매체에는 `tar.gz`와 그 옆의 `.sha256` 파일만 복사합니다. 소스 저장소, wheelhouse, 연결망의 설정 파일과 비밀값을 복사하지 않습니다. 폐쇄망 서버에서 수신 직후 파일 해시를 확인하고, 그 다음에만 압축을 풉니다.

```bash
install_dir=/opt/koda-mcp
sudo install -d -o "$(id -u)" -g "$(id -g)" -m 0750 "$install_dir/incoming"
cp /media/approved/koda-mcp-security-0.1.0-linux-amd64.tar.gz* "$install_dir/incoming/"
cd "$install_dir/incoming"
sha256sum -c koda-mcp-security-0.1.0-linux-amd64.tar.gz.sha256
tar -xzf koda-mcp-security-0.1.0-linux-amd64.tar.gz
cd koda-mcp-security-0.1.0-linux-amd64
sha256sum -c metadata/SHA256SUMS
```

해시가 다르면 압축을 사용하지 말고 매체 전달을 중단합니다.

## 3. 설정과 비밀값 준비

`config/koda_mcp.example.json`은 예시일 뿐입니다. 실제 설정은 운영 서버에서 별도 파일로 만들고 `public_host`, `allowed_origins`, 토큰 ID와 SHA-256 digest만 입력합니다. raw token은 Continue/Open WebUI의 secret 저장소에만 둡니다. 두 클라이언트에는 서로 다른 token을 사용합니다.

서버 설정 파일은 컨테이너 실행 UID `10001:10001`이 소유한 regular file이고 mode `0400`이어야 합니다.

토큰은 조직의 secret 저장소에서 생성·보관합니다. 다음 명령에서 토큰을 숨김 입력하고, 출력된 digest를 설정의 `token_sha256`에 넣습니다. 두 클라이언트는 서로 다른 값을 사용하고 사용하지 않는 예시 토큰 항목은 제거합니다.

```bash
python3 -c 'import getpass,hashlib; print(hashlib.sha256(getpass.getpass("raw token: ").encode()).hexdigest())'
```

신규 설치에서 아래와 같이 예시를 복사한 뒤 실제 `public_host`, HTTPS `allowed_origins`, 토큰 ID와 digest로 편집합니다. 기존 설정이 있으면 덮어쓰지 않고 재사용하거나 별도 백업 후 변경합니다. raw token이나 TLS 개인 키는 이 JSON에 넣지 않습니다.

```bash
if ! sudo test -e /opt/koda-mcp/koda_mcp.json; then
  sudo install -o root -g root -m 0600 config/koda_mcp.example.json /opt/koda-mcp/koda_mcp.json
fi
sudoedit /opt/koda-mcp/koda_mcp.json
sudo chown 10001:10001 /opt/koda-mcp/koda_mcp.json
sudo chmod 0400 /opt/koda-mcp/koda_mcp.json
stat -c '%u:%g %a %F %n' /opt/koda-mcp/koda_mcp.json
```

## 4. 이미지 적재와 기동

```bash
install_dir=/opt/koda-mcp
bundle_dir="$install_dir/incoming/koda-mcp-security-0.1.0-linux-amd64"
cd "$bundle_dir"
sha256sum -c "$bundle_dir/metadata/SHA256SUMS"
docker load -i image/koda-mcp-security-0.1.0-amd64.tar
export KODA_MCP_IMAGE=koda-mcp-security:accuracy-20260909
docker image inspect "$KODA_MCP_IMAGE" \
  --format '{{.Os}}/{{.Architecture}} user={{.Config.User}}'
export KODA_MCP_CONFIG_PATH=/opt/koda-mcp/koda_mcp.json
docker compose -f deploy/compose.yaml config --quiet
docker compose -f deploy/compose.yaml up -d --pull never --no-build
```

`compose.yaml`은 로컬 이미지에서만 실행하며 `platform: linux/amd64`, read-only root filesystem, capability 전체 제거, `no-new-privileges`, 내부 전용 네트워크와 `127.0.0.1:8766` 바인딩을 적용합니다. `config --quiet`가 실패하거나 이미지가 없으면 기동하지 않습니다.

기동 후 컨테이너 상태와 내부 health endpoint를 확인합니다.

```bash
export KODA_MCP_CONFIG_PATH=/opt/koda-mcp/koda_mcp.json
docker compose -f deploy/compose.yaml ps
container_id="$(docker compose -f deploy/compose.yaml ps -q koda-mcp)"
docker inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container_id"
docker exec "$container_id" python -c \
  'from urllib.request import urlopen; assert urlopen("http://127.0.0.1:8766/healthz", timeout=2).status == 200'
```

## 5. Nginx와 MCP 운영 확인

Nginx는 번들의 `deploy/nginx-mcp.conf.example`을 참고해 내부 CA가 서명한 인증서와 실제 FQDN을 설정합니다. `/mcp`만 upstream으로 전달하고 `/healthz`와 그 밖의 경로는 외부에 공개하지 않습니다.

```bash
sudo nginx -t
sudo systemctl reload nginx
curl --silent --show-error --cacert /path/to/internal-ca.pem \
  --resolve koda-mcp.internal.example:443:127.0.0.1 \
  https://koda-mcp.internal.example/healthz -o /dev/null -w '%{http_code}\n'
```

`/healthz`가 404이면 Nginx 노출 정책상 정상입니다. MCP 클라이언트에서는 `https://<KODA_FQDN>/mcp`, 내부 CA, 정확한 `Host`/`Origin`, secret 저장소의 bearer token을 사용합니다. 올바른 CA와 hostname은 성공하고 잘못된 CA·hostname은 실패해야 TLS 검증이 된 것입니다. 값이 제공되지 않은 상태는 `UNVERIFIED`로 기록합니다.

## 6. Open WebUI 연결

기존 작업 「Security 소스 분리 구현」에서 사용자가 연결 성공을 확인한 직접 연결 경로와 당시의 Host·토큰·Docker 네트워크 문제를 반영했습니다. 아래 절차는 새 폐쇄망 서버에서 다시 확인해야 합니다. 이 번들은 **KODA 서버만 포함**하며 Open WebUI와 LLM 이미지·모델은 별도로 설치되어 있어야 합니다.

### 6.1 연결 경로 선택

요청 흐름은 `브라우저 → Open WebUI 서버 → KODA /mcp`입니다. KODA 주소는 브라우저 PC가 아니라 **Open WebUI 컨테이너에서 접근 가능한 주소**여야 합니다.

| 연결 경로 | Open WebUI Server URL | KODA `public_host` |
| --- | --- | --- |
| 같은 호스트의 공유 내부 Docker 네트워크 | `http://koda-mcp:8766/mcp` | `koda-mcp:8766` |
| 내부 CA를 사용하는 Nginx HTTPS 경유 | `https://koda-mcp.internal.example/mcp` | `koda-mcp.internal.example` |

둘 중 운영할 경로 하나에 맞춰 3절의 설정을 편집합니다. `public_host`는 요청의 Host와 포트까지 정확히 일치해야 하며 한 값만 허용합니다. `allowed_origins`에는 실제 Open WebUI의 **HTTPS Origin**(예: `https://chat.internal.example`, 경로와 끝 `/` 제외)을 넣습니다. 이는 KODA URL과 별개입니다. 서버 간 요청에 Origin이 없으면 허용되지만, 있으면 등록값과 일치해야 합니다. 편집 후 소유자·0400 권한을 유지하고 기존 KODA Compose 프로젝트에서 `docker compose -f deploy/compose.yaml restart koda-mcp`를 실행합니다.

이하 KODA 명령은 4절의 번들 디렉터리와 환경변수를 사용합니다. 기존 설치가 `-p koda-mcp`로 시작됐다면 **모든 KODA Compose 명령에도 같은 `-p koda-mcp`를 붙입니다**. 다른 프로젝트명으로 다시 `up`하면 별도 컨테이너가 생길 수 있습니다.

### 6.2 같은 Docker 네트워크로 직접 연결

먼저 실제 컨테이너와 네트워크 이름을 확인합니다. 이전 환경에서는 `koda-mcp_koda_internal`이었지만 프로젝트명에 따라 달라지므로 고정해서 추측하지 않습니다.

```bash
container_id="$(docker compose -f deploy/compose.yaml ps -q koda-mcp)"
test -n "$container_id"
docker inspect --format '{{json .NetworkSettings.Networks}}' "$container_id"
docker ps --format '{{.Names}}\t{{.Image}}'
```

출력에서 실제 내부 네트워크명과 기존 Open WebUI 컨테이너명을 넣습니다. 다음 명령은 실행 중 컨테이너에 연결만 추가하며, 이미 연결돼 있으면 건너뜁니다.

```bash
export KODA_MCP_NETWORK='<확인한 koda_internal 네트워크명>'
export OPENWEBUI_CONTAINER='<기존 Open WebUI 컨테이너명>'
test "$(docker network inspect --format '{{.Internal}}' "$KODA_MCP_NETWORK")" = true
if ! docker inspect --format '{{json .NetworkSettings.Networks}}' "$OPENWEBUI_CONTAINER" \
  | python3 -c 'import json,os,sys; sys.exit(0 if os.environ["KODA_MCP_NETWORK"] in json.load(sys.stdin) else 1)'; then
  docker network connect "$KODA_MCP_NETWORK" "$OPENWEBUI_CONTAINER"
fi
```

`docker network connect`만으로는 컨테이너를 삭제·재생성할 때 연결이 유지되지 않습니다. 기존 **Open WebUI Compose 파일**에도 아래 네트워크를 합칩니다. 서비스명은 실제 이름을 사용하고, 기존 모델 서버 연결 등 모든 네트워크·볼륨·환경변수를 유지합니다. 아래 `default`는 기존 기본 네트워크를 쓰는 경우의 예시입니다.

```yaml
services:
  open-webui:
    networks:
      - default
      - koda_mcp
networks:
  koda_mcp:
    external: true
    name: ${KODA_MCP_NETWORK:?Set the existing KODA internal network name}
```

`KODA_MCP_NETWORK`는 Open WebUI 배포 환경에도 저장하고, 재생성 전 해당 Compose의 `config --quiet`로 확인합니다. KODA가 이 네트워크를 생성하므로 KODA를 먼저 기동합니다. Open WebUI가 붙어 있는 동안 KODA `down`은 네트워크 삭제에 실패할 수 있습니다. 일반 이미지 교체는 동일 프로젝트에서 `up -d --pull never --no-build`로 진행합니다.

Open WebUI 컨테이너에서 인증 없이 `/mcp`를 요청해 네트워크와 Host를 먼저 확인합니다. 다음 명령은 토큰을 사용하지 않습니다.

```bash
docker exec -i "$OPENWEBUI_CONTAINER" python - <<'PY'
from urllib.request import urlopen
from urllib.error import HTTPError
try:
    with urlopen("http://koda-mcp:8766/mcp", timeout=5) as response:
        raise SystemExit(f"expected 401, got {response.status}")
except HTTPError as error:
    print(f"HTTP {error.code}")
    if error.code != 401:
        raise SystemExit("check KODA URL and public_host")
PY
```

**401은 네트워크와 Host 검증을 통과했다는 뜻이며 인증·도구 호출 성공은 아닙니다.** Open WebUI 컨테이너에 `python`이 없으면 설치된 `python3`를 사용합니다. 이 경로는 호스트 포트 공개가 필요 없습니다. 컨테이너 안에서 `localhost:8766`은 Open WebUI 자신을 가리키므로 사용하지 않습니다.

### 6.3 HTTPS 프록시를 사용하는 경우

5절 Nginx 경로를 선택했다면 Open WebUI 서버에서 내부 DNS, 인증서 hostname, CA 체인이 검증되어야 합니다. 내부 CA 파일을 Open WebUI 컨테이너에 읽기 전용으로 마운트하고, 설치 버전이 지원하는 `AIOHTTP_CLIENT_SSL_CERT_FILE=/컨테이너/내부-ca.pem` 또는 `AIOHTTP_CLIENT_SESSION_TOOL_SERVER_SSL=/컨테이너/내부-ca.pem`을 설정합니다. TLS 검증을 `false`로 끄지 않습니다. [공식 TLS 설정](https://docs.openwebui.com/reference/env-configuration/#aiohttp_client_session_tool_server_ssl)

호스트 Nginx가 `127.0.0.1:8766`에 연결하는 구성에서는 `docker port "$container_id"`와 실제 HTTP 요청으로 포트 전달을 확인합니다. Compose의 `ports` 선언이나 `ss` 출력만으로 성공을 판단하지 않습니다. 이전 환경에서는 내부 네트워크만 연결된 컨테이너의 실제 포트 매핑이 비어 있었습니다. 일반 bridge 네트워크 추가는 KODA의 외부 통신 경로를 만들 수 있으므로, 이 경우에는 공유 내부 네트워크의 프록시 구성을 사용하거나 호스트 방화벽으로 외부 통신 차단을 별도 검증해야 합니다.

### 6.4 관리자 화면에 MCP 등록

2026-09-09 공식 문서 기준 메뉴는 **Settings → Admin → Integrations → External Tool Servers → Add Connection**입니다. 설치 릴리스에 따라 `외부 도구` 등의 번역과 메뉴 위치가 다를 수 있습니다. [Open WebUI MCP 공식 안내](https://docs.openwebui.com/features/extensibility/mcp/)

| 항목 | 입력값 |
| --- | --- |
| 이름 | `KODA Security` |
| Type | `MCP (Streamable HTTP)` |
| Server URL | 선택한 6.1절 주소. 끝은 정확히 `/mcp`, `/mcp/`와 쿼리 문자열 제외 |
| Auth | `Bearer` 또는 번역된 `보유자` |
| Key / Token | 3절에서 digest를 만들 때 사용한 **원본 토큰만** 입력 |
| 함수 이름 필터(있는 버전) | 처음에는 비워 전체 조회. 제한할 때 `koda_get_security_guidance,koda_scan_changed_files` |

전용 Bearer 입력란에는 `Bearer ` 접두어, 토큰 ID, `token_sha256`을 넣지 않습니다. KODA 서버는 digest를 보관하고 Open WebUI는 원본을 전송합니다. Open WebUI API key나 LLM API key와도 다른 값입니다. 토큰이 저장되는 Open WebUI 설정·DB·백업은 접근을 제한하고 토큰을 채팅, 명령 인자, 로그, 스크린샷에 남기지 않습니다.

저장·연결 검증 후 위 두 도구가 목록에 보이는지 확인합니다. 이전 대화의 필터 구분 문제는 **함수명 사이 쉼표**로 처리하며, 쉼표 하나만 입력하는 방식은 사용하지 않습니다. MCP 타입이 없는 버전이면 반입할 Open WebUI 버전의 네이티브 MCP 지원을 먼저 확인합니다. KODA는 Streamable HTTP 서버이므로 OpenAPI URL이나 구형 SSE 타입으로 등록하지 않습니다.

기존 잘못된 KODA 등록이 있다면 해당 연결만 비활성화하거나 제거하고 새 채팅에서 새 연결을 선택합니다. 컨테이너나 데이터 볼륨을 삭제할 필요는 없습니다. 채팅의 `+ → Integrations → Tools`에서 KODA 도구를 켜고, 사용하는 모델이 구조화된 tool calling을 지원하는지 확인합니다. 공식 문서상 v0.10.0부터 Native Function Calling이 기본입니다. 이전 버전에서는 해당 모델·채팅의 Function Calling 설정을 확인합니다. [도구 호출 모드](https://docs.openwebui.com/features/extensibility/plugin/tools/)

### 6.5 실제 호출 확인과 채팅 지침

파일 첨부가 RAG 발췌문으로 바뀌면 전체 파일 검사가 되지 않습니다. 처음에는 작은 샘플 파일의 **경로와 전체 내용**을 채팅에 직접 넣고 아래와 같이 요청합니다. KODA가 Open WebUI의 업로드 폴더나 사용자 PC를 자동으로 읽는 구조가 아닙니다.

```text
KODA의 koda_get_security_guidance를 호출하고, 아래 파일 전체를
koda_scan_changed_files에 전달해 점검해줘. standard는 sw-dev-security-49로 해줘.
실제 도구 호출 결과와 미검사 범위를 보여줘.

파일 경로: demo.py
전체 내용:
import os
command = input("command: ")
os.system(command)
```

위 코드는 점검용 문자열이며 실행하지 않습니다. Open WebUI의 도구 호출 상세에서 실제 호출 여부, 전달된 `files`의 경로·내용, 응답의 `execution_status`, `received_file_count`를 확인합니다. `completed`는 실행 완료이고 안전 판정이 아닙니다. `coverage_gaps`, `unevaluated_files`, `findings_truncated`도 확인합니다. 서버 health, 인증 없는 401, 도구 목록 조회, LLM의 실제 검사 호출은 각각 별도 확인 항목입니다.

모델의 시스템 지침에는 다음을 추가할 수 있습니다.

```text
보안 점검 요청 시 KODA 도구를 실제로 호출한다. 사용자가 제공하거나 수정한
텍스트 파일의 경로와 전체 내용만 전달하고 Git diff, RAG 발췌문, 저장소 전체를 보내지 않는다.
기본 standard는 sw-dev-security-49이며 사용자가 모든 기준을 요청한 경우만 all을 쓴다.
도구를 호출하지 못했으면 점검 완료라고 말하지 않는다.
finding마다 경로·줄, 문제 코드(redacted_snippet), 기준 항목, reason,
verification_status와 수정 예시를 설명한다. 마스킹된 값을 추측하거나 복원하지 않는다.
coverage_gaps와 unevaluated_files 및 findings_truncated를 고지하고,
finding이 없거나 completed여도 안전·준수 또는 오탐·누락 없음으로 단정하지 않는다.
```

### 6.6 연결 문제별 확인

| 증상 | 확인할 내용 |
| --- | --- |
| 이름 해석 실패·연결 거부 | Open WebUI 서버 기준 DNS/공유 네트워크, KODA 기동 상태, URL. `localhost` 오사용 확인 |
| HTTP 421 | URL의 Host와 KODA `public_host`를 포트까지 일치시키고 재시작 |
| HTTP 401 | 원본 토큰인지, 전용 입력란에 접두어가 없는지, 해당 digest와 `enabled=true`가 맞는지 확인 |
| HTTP 403 | 실제 요청에 Origin이 있으면 `allowed_origins`의 정확한 HTTPS Origin과 대조 |
| HTTP 404 / 400 | 끝 `/mcp` 확인. `/mcp/`, 쿼리 문자열, 프록시 경로 재작성 확인 |
| TLS 오류 | Open WebUI 컨테이너에 CA가 실제 마운트됐는지, hostname·체인·SSL 환경변수 확인 |
| 연결되지만 도구가 안 보임 | MCP 타입, 함수 필터, 저장 후 연결 검증, 사용자 접근 권한 확인 |
| 도구는 보이지만 모델이 호출하지 않음 | 채팅 도구 활성화, 모델 tool calling 지원, 새 채팅의 실제 호출 상세 확인 |
| 응답이 느리거나 `busy` / `timed_out` | LLM 도구 선택·서버 검사·답변 생성 시간을 분리. 서버 audit의 `duration_ms`는 전체 채팅 시간이 아님 |

Open WebUI의 `OFFLINE_MODE=true`는 외부 통신 차단 장치가 아닙니다. 관리자 MCP 연결은 별도로 동작하므로 실제 폐쇄망 경계는 Docker·호스트 방화벽으로 유지합니다. 내부 MCP 연결을 위해 전역 SSRF 보호나 TLS 검증을 해제하지 않습니다. [공식 폐쇄망·보안 설정 설명](https://docs.openwebui.com/getting-started/advanced-topics/hardening/)

## 7. 중지·교체·장애 복구

새 번들은 별도 버전 디렉터리에 풀고 검증과 이미지 load가 성공한 뒤 교체합니다. 기존 이미지와 설정 파일은 운영 보존 정책에 따라 백업한 뒤에만 정리합니다.

```bash
KODA_MCP_CONFIG_PATH=/opt/koda-mcp/koda_mcp.json \
  docker compose -f deploy/compose.yaml down
docker image ls koda-mcp-security
```

기동 실패 시 `docker compose logs --no-color koda-mcp`에서 권한, 설정 형식, 포트 충돌을 확인하고 raw token이 로그에 남지 않았는지 점검합니다. 반복 재시작이 필요하면 원인 확인 후 `docker compose stop`으로 멈춥니다.

## 8. 응답 해석과 검사 한계

Continue direct MCP와 Open WebUI 선택 MCP는 각각 별도 KODA bearer token을 사용합니다. 두 경로를 모두 활성화하지 않았다면 사용하지 않은 경로는 검증 대상이 아닙니다.

`koda_scan_changed_files`는 탐지 위치마다 별도 finding을 반환합니다. 각 finding의 `start_line`, `end_line`, `redacted_snippet`, `reason`, 적용 기준과 권고조치를 사용해 LLM이 문제 코드·기준 항목·사유·수정 예시를 각각 출력하도록 설정합니다. snippet의 알려진 비밀번호·토큰·키는 `<redacted>`로 대체되며 복원하면 안 됩니다. `findings_truncated=true`이면 모든 탐지 결과가 반환된 것이 아닙니다.

응답의 `unevaluated_files`는 검사하지 않은 파일과 범위를 보여줍니다. 각 항목의 `scope`는 `code`, `secrets`, `configuration_text`, `all_checks` 중 하나입니다. 미지원 텍스트 형식은 코드·비밀값·일반 텍스트 설정 검사가 각각 제외되며, 파일명별 의존성/설정 검사는 별도로 실행될 수 있습니다. `reason`은 `unsupported_code_file_type`, `unsupported_text_file_type`, `line_length_limit` 중 하나입니다. 지원하지 않는 언어는 코드 검사를 하지 않고, 한 줄이라도 2,000바이트를 넘으면 해당 파일의 모든 검사를 건너뛰며, 이름이 표시됐다고 해서 탐지된 것으로 해석하지 않습니다.

`coverage_gaps`에는 의존성 CVE를 평가하지 않았다는 `dependency_cve_not_evaluated`, 함수 간 흐름을 추적하지 않았다는 `interprocedural_dataflow_not_evaluated`, 단일 기준 선택으로 일부 규칙 결과가 제외될 수 있다는 안내가 포함될 수 있습니다. 코어의 `verification_note`는 응답의 `reason`에 보존되므로 이를 근거로 표시하고, 비밀값 대입문은 마스킹된 상태로만 전달합니다. 현재 응답의 전역 안전 상한은 200개 finding이므로 `findings_truncated=true`를 반드시 우선 고지합니다.

기준을 생략하면 `sw-dev-security-49`가 적용됩니다. 사용자가 모든 기준을 요청한 경우에만 `standard=all`을 전달하며, 이 모드는 KODA core finding을 기준으로 제거하지 않고 지원되는 모든 기준 매핑을 각 finding에 포함합니다.

탐지는 산출물에 고정된 KODA core 규칙을 그대로 사용합니다. MCP 계층은 규칙을 재구현하거나 finding을 억제하지 않으며 기준 필터·매핑, 입력 제한, 비밀값 마스킹과 응답 제한만 적용합니다.

호스트 Nginx 적용 전 `nginx -t`를 통과시킵니다. 적용 후에는 올바른 내부 CA와 FQDN으로 `/mcp`가 연결되고 `/healthz`와 다른 경로는 404인지 확인하며, 잘못된 CA와 hostname 연결은 반드시 실패해야 합니다. 인증서·CA·FQDN이 제공되지 않은 상태에서는 TLS 검증을 완료로 표시하지 않습니다.
