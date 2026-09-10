# 폐쇄망 Docker 번들 배포

2026-09-10 개정. 「Security 소스 분리 구현」의 설치 오류·수정·사용자 성공 확인을 현재 구현과 대조했습니다. 기본 경로는 당시 요청한 **`~/koda-mcp`, 일반 사용자 계정 + sudo, Open WebUI와 공유 내부 Docker 네트워크**입니다. Open WebUI만 연결할 경우 5절의 Nginx는 생략하고 6절로 이동합니다. 이전 대화의 구버전 해시·이미지 태그를 새 반입물에 적용하지 않습니다.

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
release_dir="$PWD/dist/install-20260910"
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
install_dir="$HOME/koda-mcp"
release_id=install-20260910
mkdir -p "$install_dir/releases"
test ! -e "$install_dir/releases/$release_id" || { echo '이미 있는 릴리스입니다. release_id를 바꾸세요.'; exit 1; }
mkdir -m 0750 "$install_dir/releases/$release_id"
cd "$install_dir/releases/$release_id"
cp /media/approved/koda-mcp-security-0.1.0-linux-amd64.tar.gz .
cp /media/approved/koda-mcp-security-0.1.0-linux-amd64.tar.gz.sha256 .
sha256sum -c koda-mcp-security-0.1.0-linux-amd64.tar.gz.sha256
tar -xzf koda-mcp-security-0.1.0-linux-amd64.tar.gz
cd koda-mcp-security-0.1.0-linux-amd64
sha256sum -c metadata/SHA256SUMS
bundle_dir="$PWD"
```

해시가 다르면 압축을 사용하지 말고 매체 전달을 중단합니다.

아래는 폐쇄망 서버의 **Bash 세션**에서 실행합니다. 새 터미널에서는 `install_dir="$HOME/koda-mcp"`와 실제 반입 디렉터리의 절대경로로 `bundle_dir`를 다시 설정하고 다음 블록을 실행합니다. 기존 설치를 바꾸는 경우 먼저 실행 컨테이너의 `com.docker.compose.project` 라벨로 프로젝트명을 확인합니다. 당시 값은 `koda-mcp`였지만 다른 값이면 `KODA_PROJECT`를 그 값으로 설정합니다. `user0` 계정 자체의 UID를 바꾸지 않습니다.

```bash
sudo docker ps --format 'table {{.Names}}\t{{.Label "com.docker.compose.project"}}\t{{.Image}}'
export KODA_PROJECT=koda-mcp
export KODA_MCP_CONFIG_PATH="$install_dir/koda_mcp.json"
export KODA_MCP_IMAGE=koda-mcp-security:accuracy-20260909
kd() { sudo docker "$@"; }
kc() {
  sudo env KODA_MCP_CONFIG_PATH="$KODA_MCP_CONFIG_PATH" KODA_MCP_IMAGE="$KODA_MCP_IMAGE" \
    docker compose -p "$KODA_PROJECT" -f "$bundle_dir/deploy/compose.yaml" "$@"
}
```

이후 `kd`는 `sudo docker`, `kc`는 절대경로·프로젝트명·환경변수를 지정한 Compose 호출입니다.

`sudo`에서 환경변수가 빠지지 않도록 설정 경로와 이미지 태그를 매번 `sudo env`로 전달합니다. 기존 설정을 재사용할 때는 `KODA_MCP_CONFIG_PATH`를 실제 파일의 절대경로로 변경합니다. 따옴표 안의 `~`, `./koda_mcp.json`은 사용하지 않습니다. 상대경로가 Compose 파일이 있는 `deploy/` 기준으로 해석되어 마운트가 실패했던 문제를 예방합니다.

## 3. 설정과 비밀값 준비

`config/koda_mcp.example.json`은 예시일 뿐입니다. 실제 설정은 운영 서버에서 별도 파일로 만들고 `public_host`, `allowed_origins`, 토큰 ID와 SHA-256 digest만 입력합니다. raw token은 Continue/Open WebUI의 secret 저장소에만 둡니다. 두 클라이언트에는 서로 다른 token을 사용합니다.

서버 설정 파일은 컨테이너 실행 UID `10001:10001`이 소유한 regular file이고 mode `0400`이어야 합니다.

토큰은 조직의 secret 저장소에서 생성·보관합니다. 다음 명령에서 토큰을 숨김 입력하고, 출력된 digest를 설정의 `token_sha256`에 넣습니다. 두 클라이언트는 서로 다른 값을 사용하고 사용하지 않는 예시 토큰 항목은 제거합니다.

```bash
python3 -c 'import getpass,hashlib; print(hashlib.sha256(getpass.getpass("raw token: ").encode()).hexdigest())'
```

신규 설치에서 아래와 같이 예시를 복사한 뒤 실제 `public_host`, HTTPS `allowed_origins`, 토큰 ID와 digest로 편집합니다. 기존 설정이 있으면 덮어쓰지 않고 재사용하거나 별도 백업 후 변경합니다. raw token이나 TLS 개인 키는 이 JSON에 넣지 않습니다.

```bash
if ! sudo test -e "$KODA_MCP_CONFIG_PATH"; then
  sudo install -o root -g root -m 0600 "$bundle_dir/config/koda_mcp.example.json" "$KODA_MCP_CONFIG_PATH"
fi
sudoedit "$KODA_MCP_CONFIG_PATH"
sudo python3 -m json.tool "$KODA_MCP_CONFIG_PATH" >/dev/null
sudo chown 10001:10001 "$KODA_MCP_CONFIG_PATH"
sudo chmod 0400 "$KODA_MCP_CONFIG_PATH"
sudo stat -c '%u:%g %a %F %n' "$KODA_MCP_CONFIG_PATH"
```

Open WebUI만 연결하는 최소 JSON은 다음과 같습니다. 실제 HTTPS Open WebUI 주소와 앞서 계산한 64자리 소문자 SHA-256으로 바꿉니다. 사용하지 않는 Continue 토큰과 0/1로 채운 예시 digest는 제거합니다.

```json
{
  "public_host": "koda-mcp:8766",
  "allowed_origins": ["https://chat.internal.example"],
  "tokens": [
    {
      "id": "openwebui-service",
      "token_sha256": "<원본 토큰에서 계산한 64자리 SHA-256>",
      "enabled": true
    }
  ]
}
```

`allowed_origins`는 비어 있으면 안 되며 HTTPS 주소만 허용합니다. 토큰 ID·digest 중복과 모든 토큰 비활성화도 기동 오류입니다. JSON 주석·끝 쉼표·알 수 없는 필드는 넣지 않습니다. `chmod 666/777`로 해결하지 않습니다. 정상 소유권·권한은 `10001:10001 400 regular file`입니다.

## 4. 이미지 적재와 기동

```bash
cd "$bundle_dir"
sha256sum -c "$bundle_dir/metadata/SHA256SUMS"
kd load -i image/koda-mcp-security-0.1.0-amd64.tar
kd image inspect "$KODA_MCP_IMAGE" \
  --format '{{.Os}}/{{.Architecture}} user={{.Config.User}}'
sudo test -f "$KODA_MCP_CONFIG_PATH"
kd run --rm --pull never --platform linux/amd64 --network none --user 10001:10001 \
  --entrypoint python \
  --mount "type=bind,source=$KODA_MCP_CONFIG_PATH,target=/run/secrets/koda_mcp.json,readonly" \
  "$KODA_MCP_IMAGE" -c 'from koda_mcp.server import load_config; load_config(); print("CONFIG_OK")'
kc config --quiet
kc up -d --pull never --no-build koda-mcp
```

하나라도 실패하면 다음 단계로 진행하지 않습니다. `CONFIG_OK`는 실제 컨테이너 UID로 설정을 읽고 검증했다는 뜻입니다. JSON 문법 검사만으로는 소유권·필수 항목을 확인할 수 없습니다. 존재하지 않는 bind 원본이 디렉터리로 생성되는 것을 막도록 사전 검사에 `--mount`를 사용합니다. `No such image`이면 `docker load`가 표시한 태그와 `KODA_MCP_IMAGE`를 대조합니다.

`compose.yaml`은 로컬 이미지에서만 실행하며 `platform: linux/amd64`, read-only root filesystem, capability 전체 제거, `no-new-privileges`, 내부 전용 네트워크와 `127.0.0.1:8766` 바인딩을 적용합니다. `config --quiet`가 실패하거나 이미지가 없으면 기동하지 않습니다.

기동 후 컨테이너 상태와 내부 health endpoint를 확인합니다.

```bash
kc ps
container_id="$(kc ps -q koda-mcp)"
test -n "$container_id"
kd inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container_id"
kd exec "$container_id" python -c \
  'from urllib.request import urlopen; assert urlopen("http://127.0.0.1:8766/healthz", timeout=2).status == 200'
```

## 5. Nginx와 MCP 운영 확인

같은 Docker 호스트의 Open WebUI 내부 연결만 사용하면 이 절을 생략합니다. 호스트 Nginx 경로는 6.3절에서 실제 포트 게시를 확인한 뒤 진행합니다. Nginx가 컨테이너라면 템플릿의 `127.0.0.1`은 Nginx 자신이므로 공유 내부 네트워크와 `proxy_pass http://koda-mcp:8766/mcp`가 필요합니다.

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

사진처럼 `kd port`가 `No public port 8766/tcp`를 출력하고 호스트에서 `curl 127.0.0.1:8766`이 `connection refused`가 되어도, 현재 Compose의 `koda_internal: internal: true`를 쓰는 **직접 연결 경로에서는 예상되는 결과**입니다. `kd exec ... /healthz`가 `running healthy`이면 KODA는 정상입니다. 이 경우 5절과 6.3절의 호스트 Nginx·CA·호스트 포트 명령을 실행하지 말고 바로 6.2절로 이동합니다. 호스트 Nginx를 반드시 써야 할 때만 6.3절의 `koda_host` 추가 구성을 적용합니다.

현재 화면에서 다음 한 줄이 성공하면 KODA 기동 확인을 끝냅니다.

```bash
container_id="$(kc ps -q koda-mcp)"
kd exec "$container_id" python -c \
  'from urllib.request import urlopen; print(urlopen("http://127.0.0.1:8766/healthz", timeout=2).read().decode())'
```

그 다음에는 호스트 `127.0.0.1:8766`이 아니라 Open WebUI 컨테이너에서 `http://koda-mcp:8766/mcp`를 확인합니다. 인증 없는 요청의 기대 응답은 `401`입니다.

| 연결 경로 | Open WebUI Server URL | KODA `public_host` |
| --- | --- | --- |
| 같은 호스트의 공유 내부 Docker 네트워크 | `http://koda-mcp:8766/mcp` | `koda-mcp:8766` |
| 내부 CA를 사용하는 Nginx HTTPS 경유 | `https://koda-mcp.internal.example/mcp` | `koda-mcp.internal.example` |

둘 중 운영할 경로 하나에 맞춰 3절의 설정을 편집합니다. `public_host`는 요청의 Host와 포트까지 정확히 일치해야 하며 한 값만 허용합니다. `allowed_origins`에는 실제 Open WebUI의 **HTTPS Origin**(예: `https://chat.internal.example`, 경로와 끝 `/` 제외)을 넣습니다. 이는 KODA URL과 별개입니다. 서버 간 요청에 Origin이 없으면 허용되지만, 있으면 등록값과 일치해야 합니다. 편집 후 소유자·0400 권한과 `CONFIG_OK`를 확인하고 `kc up -d --pull never --no-build --force-recreate koda-mcp`로 적용합니다.

이하 명령은 2절에서 정의한 `kd`·`kc`를 사용합니다. 기존 설치와 다른 프로젝트명으로 `up`하면 별도 컨테이너가 생길 수 있습니다.

### 6.2 같은 Docker 네트워크로 직접 연결

먼저 실제 컨테이너와 네트워크 이름을 확인합니다. 이전 환경에서는 `koda-mcp_koda_internal`이었지만 프로젝트명에 따라 달라지므로 고정해서 추측하지 않습니다.

```bash
container_id="$(kc ps -q koda-mcp)"
test -n "$container_id"
kd inspect --format '{{json .NetworkSettings.Networks}}' "$container_id"
kd ps --format '{{.Names}}\t{{.Image}}'
```

출력에서 실제 내부 네트워크명과 기존 Open WebUI 컨테이너명을 넣습니다. 다음 명령은 실행 중 컨테이너에 연결만 추가하며, 이미 연결돼 있으면 건너뜁니다.

```bash
export KODA_MCP_NETWORK='<확인한 koda_internal 네트워크명>'
export OPENWEBUI_CONTAINER='<기존 Open WebUI 컨테이너명>'
test "$(kd network inspect --format '{{.Internal}}' "$KODA_MCP_NETWORK")" = true || exit 1
if ! kd inspect --format '{{json .NetworkSettings.Networks}}' "$OPENWEBUI_CONTAINER" \
  | python3 -c 'import json,os,sys; sys.exit(0 if os.environ["KODA_MCP_NETWORK"] in json.load(sys.stdin) else 1)'; then
  kd network connect "$KODA_MCP_NETWORK" "$OPENWEBUI_CONTAINER"
fi
kd network inspect "$KODA_MCP_NETWORK" --format '{{range .Containers}}{{println .Name}}{{end}}'
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
kd exec -i "$OPENWEBUI_CONTAINER" python - <<'PY'
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

먼저 호스트 Nginx의 upstream을 진단합니다. 아래 HTTP 401은 토큰을 보내지 않은 정상 거부이며, 421이면 프록시용 `public_host`와 Host가 다른 것입니다.

```bash
container_id="$(kc ps -q koda-mcp)"
kc config --quiet
kd inspect "$container_id" --format 'requested={{json .HostConfig.PortBindings}} actual={{json .NetworkSettings.Ports}}'
kd port "$container_id" 8766/tcp
curl --connect-timeout 3 -sS -o /dev/null -w '%{http_code}\n' \
  -H 'Host: koda-mcp.internal.example' http://127.0.0.1:8766/mcp
```

`ss -lntp`에 안 보여도 Docker NAT로 전달될 수 있습니다. 반대로 Compose에 `ports`가 있어도 실제 게시 성공을 뜻하지 않습니다. `requested`에 바인딩이 있고 `actual={}`였던 이전 환경에서는 아래처럼 `deploy/compose.yaml`에 호스트용 bridge를 추가해 포트 게시를 복구했습니다. **이 선택지는 호스트 Nginx가 필요하고 추가 bridge의 외부 통신을 방화벽으로 통제한 경우에만 적용합니다.** Open WebUI 직접 연결에는 필요 없습니다.

```yaml
services:
  koda-mcp:
    networks:
      - koda_internal
      - koda_host
networks:
  koda_internal:
    internal: true
  koda_host:
    driver: bridge
```

위 조각은 기존 Compose에 병합하며 나머지 보안 설정과 `127.0.0.1:8766:8766`은 유지합니다. 병합 후 다음 명령으로 KODA만 재생성하고 게시를 확인합니다. `restart`만으로는 이미지·포트·네트워크 변경이 반영되지 않습니다.

```bash
kc config --quiet
kc up -d --pull never --no-build --force-recreate koda-mcp
container_id="$(kc ps -q koda-mcp)"
kd port "$container_id" 8766/tcp
curl --connect-timeout 3 -fsS http://127.0.0.1:8766/healthz
```

기대값은 `127.0.0.1:8766`과 `{"status":"ok"}`입니다. 실패하면 `kc logs --tail=100 koda-mcp`의 포트 충돌, 실제 컨테이너 프로젝트 라벨, 적용한 Compose 파일을 확인합니다. NAT/방화벽 확인은 `sudo iptables -t nat -S DOCKER` 또는 `sudo nft list ruleset`에서 수행하며 Docker 데몬 전체를 무조건 재시작하지 않습니다. 추가 bridge를 썼다면 기본 번들의 내부 네트워크 차단 검증은 이 변경된 구성을 증명하지 않으므로 실제 방화벽 경계에서 다시 확인합니다.

5절 Nginx 경로를 선택했다면 Open WebUI 서버에서 내부 DNS, 인증서 hostname, CA 체인이 검증되어야 합니다. 내부 CA 파일을 Open WebUI 컨테이너에 읽기 전용으로 마운트하고, 설치 버전이 지원하는 `AIOHTTP_CLIENT_SSL_CERT_FILE=/컨테이너/내부-ca.pem` 또는 `AIOHTTP_CLIENT_SESSION_TOOL_SERVER_SSL=/컨테이너/내부-ca.pem`을 설정합니다. TLS 검증을 `false`로 끄지 않습니다. [공식 TLS 설정](https://docs.openwebui.com/reference/env-configuration/#aiohttp_client_session_tool_server_ssl)

호스트 Nginx가 `127.0.0.1:8766`에 연결하는 구성에서는 `docker port "$container_id"`와 실제 HTTP 요청으로 포트 전달을 확인합니다. Compose의 `ports` 선언이나 `ss` 출력만으로 성공을 판단하지 않습니다. 이전 환경에서는 내부 네트워크만 연결된 컨테이너의 실제 포트 매핑이 비어 있었습니다. 일반 bridge 네트워크 추가는 KODA의 외부 통신 경로를 만들 수 있으므로, 이 경우에는 공유 내부 네트워크의 프록시 구성을 사용하거나 호스트 방화벽으로 외부 통신 차단을 별도 검증해야 합니다.

### 6.4 관리자 화면에 MCP 등록

2026-09-10 공식 문서 기준 메뉴는 **Settings → Admin → Integrations → External Tool Servers → Add Connection**입니다. 네이티브 MCP는 v0.6.31 이상에서 지원하며 설치 릴리스에 따라 메뉴 번역이 다를 수 있습니다. [Open WebUI MCP 공식 안내](https://docs.openwebui.com/features/extensibility/mcp/)

| 항목 | 입력값 |
| --- | --- |
| 이름 | `KODA Security` |
| ID(입력 가능한 버전) | `koda_mcp`. 읽기 전용이면 자동 생성값 유지. 서버 JSON의 토큰 ID와 일치할 필요 없음 |
| Type | `MCP (Streamable HTTP)` |
| Server URL | 선택한 6.1절 주소. 끝은 정확히 `/mcp`, `/mcp/`와 쿼리 문자열 제외 |
| Auth | `Bearer` 또는 번역된 `보유자` |
| Key / Token | 3절에서 digest를 만들 때 사용한 **원본 토큰만** 입력 |
| 함수 이름 필터(있는 버전) | 처음에는 비워 전체 조회. 제한할 때 `koda_get_security_guidance,koda_scan_changed_files` |

전용 Bearer 입력란에는 `Bearer ` 접두어, 토큰 ID, `token_sha256`을 넣지 않습니다. KODA 서버는 digest를 보관하고 Open WebUI는 원본을 전송합니다. Open WebUI API key나 LLM API key와도 다른 값입니다. 토큰이 저장되는 Open WebUI 설정·DB·백업은 접근을 제한하고 토큰을 채팅, 명령 인자, 로그, 스크린샷에 남기지 않습니다.

저장·연결 검증 후 위 두 도구가 목록에 보이는지 확인합니다. **빈 함수 필터에서 등록·호출이 실패하거나 도구가 안 보이면 쉼표 하나 `,`를 넣어 저장하고 다시 확인합니다.** 참조 대화에서 사용자가 이 방법으로 성공을 확인했으며 공식 문서에도 빈 필터 파싱 문제의 우회 방법으로 안내되어 있습니다. 이전 설치 문서의 “쉼표 하나를 사용하지 않는다”는 설명은 잘못되어 정정했습니다. 이는 함수명 두 개를 쉼표로 구분하는 명시적 필터와 다른 설정입니다. [공식 함수 필터 문제 해결](https://docs.openwebui.com/features/extensibility/mcp/#function-name-filter-list)

`접근/Access`에서 사용할 사용자 또는 그룹에 읽기 권한을 부여하고 연결 활성화 스위치를 켠 뒤 저장합니다. 화면 ID가 붙어 도구명이 표시될 수 있으므로 실제 목록도 확인합니다. MCP를 OpenAPI 타입으로 등록했거나 `mcpServers` JSON을 잘못 붙여 무한 로딩이 생기면, 관리자 Integrations에서 해당 연결을 비활성화·삭제하고 새로고침한 뒤 올바른 MCP 타입으로 다시 등록합니다.

기존 등록을 교체할 때는 관리자 화면에서 해당 KODA 연결을 비활성화하고 삭제합니다. 기존 채팅의 도구 선택과 Workspace → Models의 기본 도구 설정에서도 이전 연결을 해제합니다. 브라우저를 새로고침하고 새 채팅에서 `+ → Integrations → Tools`로 새 KODA를 켭니다. 화면이 계속 갱신되지 않거나 재시작 안내가 뜨면 기존 Open WebUI 운영 절차에 따라 재시작합니다. 등록 삭제는 KODA 컨테이너·설정·Open WebUI 데이터 볼륨 삭제가 아닙니다.

도구가 보여도 모델이 호출하지 않으면 모델의 구조화된 tool calling 지원과 해당 모델·채팅의 Function Calling 설정을 확인합니다. [도구 호출 모드](https://docs.openwebui.com/features/extensibility/plugin/tools/)

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
| `sudo: command not found` 뒤에 `^[[200~`가 보임 | 터미널의 붙여넣기 제어문자가 명령 앞에 섞인 것입니다. `Ctrl+C` 후 명령을 직접 다시 입력합니다. 다음처럼 sudo 비밀번호 프롬프트가 나오면 sudo 자체는 설치되어 있습니다. |
| `nginx: command not found` / `Unit nginx.service not found` | 호스트에 Nginx가 설치·등록되지 않은 상태입니다. Open WebUI 직접 연결은 Nginx가 필요 없으므로 5·6.3절을 건너뜁니다. HTTPS 프록시가 필요할 때만 조직 패키지로 Nginx를 별도 설치하고 6.3절을 적용합니다. |
| `curl: (77) error setting certificate file: /path/to/...` | 문서의 예시 경로를 실제 내부 CA 경로로 바꾸지 않은 것입니다. 직접 Docker 연결에서는 이 명령을 실행하지 않습니다. |
| 연결되지만 도구가 안 보임 | MCP 타입, 함수 필터, 저장 후 연결 검증, 사용자 접근 권한 확인 |
| 빈 함수 필터에서 실패 | 쉼표 하나 `,` 우회, 저장, 새로고침, 새 채팅 순서로 확인 |
| 도구는 보이지만 모델이 호출하지 않음 | 채팅 도구 활성화, 모델 tool calling 지원, 새 채팅의 실제 호출 상세 확인 |
| 응답이 느리거나 `busy` / `timed_out` | LLM 도구 선택·서버 검사·답변 생성 시간을 분리. 서버 audit의 `duration_ms`는 전체 채팅 시간이 아님 |

Open WebUI의 `OFFLINE_MODE=true`는 외부 통신 차단 장치가 아닙니다. 관리자 MCP 연결은 별도로 동작하므로 실제 폐쇄망 경계는 Docker·호스트 방화벽으로 유지합니다. 내부 MCP 연결을 위해 전역 SSRF 보호나 TLS 검증을 해제하지 않습니다. [공식 폐쇄망·보안 설정 설명](https://docs.openwebui.com/getting-started/advanced-topics/hardening/)

## 7. 중지·교체·장애 복구

### 7.1 설정 오류·재시작 반복

기동 시 설정 오류를 발견하면 서버가 종료하는 것이 현재 동작입니다. `Restarting`이면 반복 기동을 멈추고 3절의 JSON/권한 및 4절의 `CONFIG_OK`를 확인합니다. 실패 메시지와 권한 메타데이터만 확인하고 JSON 전체를 공유하지 않습니다.

```bash
kc logs --tail=100 koda-mcp
kc stop koda-mcp
sudo stat -c '%u:%g %a %F %n' "$KODA_MCP_CONFIG_PATH"
sudo python3 -m json.tool "$KODA_MCP_CONFIG_PATH" >/dev/null
```

| 오류 | 수정 |
| --- | --- |
| `configuration is unavailable` / mount 실패 | 파일명 `koda_mcp.json`, 절대경로, 파일 존재 여부, 심볼릭 링크 여부 확인 |
| `owner-readable mode 0400` | 파일만 UID/GID 10001:10001, mode 0400으로 복구 |
| `configuration is invalid` / `unknown fields` | UTF-8 JSON, 필수 키, 주석·끝 쉼표·추가 키 제거 |
| `allowed_origins` 오류 | 비어 있지 않은 HTTPS Origin 목록, 경로·끝 `/`·중복 제거 |
| `token record is invalid` | `id`, 64자리 소문자 digest, JSON boolean `enabled` 확인 |
| 토큰 중복 / enabled token 없음 | ID·digest 중복 제거, 실제 사용할 토큰 하나 이상 활성화 |
| Compose 환경변수 누락 | 현재 Bash 세션에서 2절 변수와 `kc` 함수를 다시 정의 |

### 7.2 새 이미지 교체와 되돌리기

새 번들은 2절처럼 별도 릴리스 디렉터리에 풀어 원본을 보존합니다. 변경 전 실행 이미지 ID·설정 파일·기존 Compose를 보관합니다. 아래에서 `old_bundle_dir`은 **현재 실행에 사용한 기존 번들**이어야 합니다. `kc`는 최신 `bundle_dir`를 참조하므로 변수 변경 순서를 지킵니다.

```bash
old_bundle_dir="$bundle_dir"
container_id="$(kc ps -q koda-mcp)"
old_image_id="$(kd inspect --format '{{.Image}}' "$container_id")"
backup_dir="$(mktemp -d "$install_dir/backup.XXXXXX")"
sudo cp -p "$KODA_MCP_CONFIG_PATH" "$backup_dir/koda_mcp.json"
cp "$old_bundle_dir/deploy/compose.yaml" "$backup_dir/compose.yaml"
```

새 디렉터리로 `bundle_dir`를 바꾼 뒤 4절의 이미지 load·설정 사전 검사를 수행합니다. 이전에 적용한 운영 네트워크 변경도 새 Compose에 검토·반영한 뒤 실행합니다.

```bash
kc config --quiet
kc up -d --pull never --no-build --force-recreate koda-mcp
kc ps
kc logs --tail=100 koda-mcp
```

4절 컨테이너 health와 6절 Open WebUI 실제 호출이 모두 성공해야 교체 완료입니다. 실패하면 기존 설정과 Compose·이미지로 되돌립니다. 아래 변수는 같은 세션에서 유지되어야 하며, 새 세션에서는 기록한 실제 값으로 복구합니다.

```bash
sudo cp -p "$backup_dir/koda_mcp.json" "$KODA_MCP_CONFIG_PATH"
sudo chown 10001:10001 "$KODA_MCP_CONFIG_PATH"
sudo chmod 0400 "$KODA_MCP_CONFIG_PATH"
export KODA_MCP_IMAGE="$old_image_id"
sudo env KODA_MCP_CONFIG_PATH="$KODA_MCP_CONFIG_PATH" KODA_MCP_IMAGE="$KODA_MCP_IMAGE" \
  docker compose -p "$KODA_PROJECT" -f "$backup_dir/compose.yaml" \
  up -d --pull never --no-build --force-recreate koda-mcp
```

설정 내용만 편집해도 bind 원본 inode가 교체될 수 있으므로 재생성 후 검증하는 편이 확실합니다. 포트·네트워크·이미지는 반드시 `up --force-recreate`로 적용합니다. 다른 컨테이너가 공유 네트워크에 붙은 상태에서 `down`은 네트워크 삭제에 실패할 수 있으므로 일반 교체는 `down` 없이 수행합니다. 정상 확인 전 백업·구 이미지·Open WebUI 볼륨을 삭제하지 않습니다.

### 7.3 검사 지연과 실패 응답

`kc logs --tail=100 koda-mcp`의 `duration_ms`와 Open WebUI 호출 상세를 대조해 모델의 도구 선택, KODA 실행, 모델 답변 생성을 구분합니다. KODA는 한 번에 한 검사만 실행하고 동시 요청은 `busy`로 반환하므로 대기열로 오해하지 않습니다. `timed_out`·`failed`·`rejected`는 점검 완료가 아니며 파일 크기·입력 계약·서버 로그를 확인합니다. 임시 파일 정리 실패로 서버가 종료한 경우도 성공으로 표시하지 않습니다.

## 8. 응답 해석과 검사 한계

Continue direct MCP와 Open WebUI 선택 MCP는 각각 별도 KODA bearer token을 사용합니다. 두 경로를 모두 활성화하지 않았다면 사용하지 않은 경로는 검증 대상이 아닙니다.

`koda_scan_changed_files`는 탐지 위치마다 별도 finding을 반환합니다. 각 finding의 `start_line`, `end_line`, `redacted_snippet`, `reason`, 적용 기준과 권고조치를 사용해 LLM이 문제 코드·기준 항목·사유·수정 예시를 각각 출력하도록 설정합니다. snippet의 알려진 비밀번호·토큰·키는 `<redacted>`로 대체되며 복원하면 안 됩니다. `findings_truncated=true`이면 모든 탐지 결과가 반환된 것이 아닙니다.

응답의 `unevaluated_files`는 검사하지 않은 파일과 범위를 보여줍니다. 각 항목의 `scope`는 `code`, `secrets`, `configuration_text`, `all_checks` 중 하나입니다. 미지원 텍스트 형식은 코드·비밀값·일반 텍스트 설정 검사가 각각 제외되며, 파일명별 의존성/설정 검사는 별도로 실행될 수 있습니다. `reason`은 `unsupported_code_file_type`, `unsupported_text_file_type`, `line_length_limit` 중 하나입니다. 지원하지 않는 언어는 코드 검사를 하지 않고, 한 줄이라도 2,000바이트를 넘으면 해당 파일의 모든 검사를 건너뛰며, 이름이 표시됐다고 해서 탐지된 것으로 해석하지 않습니다.

`coverage_gaps`에는 의존성 CVE를 평가하지 않았다는 `dependency_cve_not_evaluated`, 함수 간 흐름을 추적하지 않았다는 `interprocedural_dataflow_not_evaluated`, 단일 기준 선택으로 일부 규칙 결과가 제외될 수 있다는 안내가 포함될 수 있습니다. 코어의 `verification_note`는 응답의 `reason`에 보존되므로 이를 근거로 표시하고, 비밀값 대입문은 마스킹된 상태로만 전달합니다. 현재 응답의 전역 안전 상한은 200개 finding이므로 `findings_truncated=true`를 반드시 우선 고지합니다.

기준을 생략하면 `sw-dev-security-49`가 적용됩니다. 사용자가 모든 기준을 요청한 경우에만 `standard=all`을 전달하며, 이 모드는 KODA core finding을 기준으로 제거하지 않고 지원되는 모든 기준 매핑을 각 finding에 포함합니다.

탐지는 산출물에 고정된 KODA core 규칙을 그대로 사용합니다. MCP 계층은 규칙을 재구현하거나 finding을 억제하지 않으며 기준 필터·매핑, 입력 제한, 비밀값 마스킹과 응답 제한만 적용합니다.

호스트 Nginx 적용 전 `nginx -t`를 통과시킵니다. 적용 후에는 올바른 내부 CA와 FQDN으로 `/mcp`가 연결되고 `/healthz`와 다른 경로는 404인지 확인하며, 잘못된 CA와 hostname 연결은 반드시 실패해야 합니다. 인증서·CA·FQDN이 제공되지 않은 상태에서는 TLS 검증을 완료로 표시하지 않습니다.

## 9. 이전 대화의 오류·수정 반영표

초기 추정 뒤 원인이 바뀐 항목은 최종 증거를 기준으로 정리했습니다. 예전 압축본의 “31/34/35개 테스트”와 해시는 현재 파일의 검증값이 아니며, 과거 원본 규칙 해시 일치도 이후 탐지 수정까지 동일하다는 뜻은 아닙니다.

| 대화에서 발생한 문제 또는 수정 | 이 문서의 적용 위치 |
| --- | --- |
| 설치 장소가 `/opt`, 홈 디렉터리 등으로 바뀌며 혼동 | 2절: `~/koda-mcp/releases`로 통일, 기존 경로 별도 지정 |
| 동일 파일명 압축본·백업본의 버전과 해시 혼동 | 1·2절: 릴리스 디렉터리 분리, 외부·내부 해시 대조 |
| 설정 파일명 오타, 상대경로가 `deploy/`로 해석됨 | 2·4절: 절대경로와 실제 regular file 사전 확인 |
| sudo에서 설정 경로·이미지 태그 누락 | 2절: `kc`가 매번 `sudo env`로 전달 |
| user0 계정·UID 혼동, 666/777 권한 후 기동 실패 | 3절: 사용자 유지, 설정 파일만 10001:10001 / 0400 |
| mount 후 설정 오류로 무한 재시작 | 4·7.1절: `CONFIG_OK` 사전 검사와 `stop` 후 진단 |
| Continue 예시 토큰·0으로 채운 digest가 남음 | 3절: Open WebUI 단독 JSON과 미사용 항목 제거 |
| 원본 토큰·digest·Open WebUI API key 혼동 | 3·6.4절: 발급·해시·입력 위치 구분 |
| Compose ports와 실제 게시 상태 불일치 | 6.3절: requested/actual 비교, KODA만 재생성 |
| `ss` 결과 없음, `No public port`, internal 네트워크 | 6.2·6.3절: 내부 직접 연결과 호스트 프록시 분기, bridge 영향 명시 |
| `koda-mcp.ssis`와 `koda-mcp:8766` Host 불일치 | 6.1·6.3절: 421과 401 구분, URL과 Host 통일 |
| Open WebUI 연결 성공인데 채팅에 도구가 없음 | 6.4절: 쉼표 하나 우회·접근 권한·활성화·새 채팅 |
| MCP ID가 무엇인지 혼동 | 6.4절: Open WebUI 식별자와 토큰 ID 분리 |
| 기존 등록 삭제·재등록·컨테이너 교체 혼동 | 6.4·7.2절: 등록만 삭제, 이미지 교체와 롤백 별도 |
| Open WebUI 재생성 뒤 네트워크 연결 소실 | 6.2절: 기존 Compose에 external 네트워크 영구 반영 |
| 코드 줄·기준 항목이 없던 구 응답 | 6.5·8절: 마스킹된 snippet과 각 finding별 기준·사유 |
| 자체 기준 제거·SW49 기본·all 매핑 추가 | 6.5·8절: 기본 SW49, 명시 요청만 all, 관련 분류를 위반 확정으로 표현하지 않음 |
| 점검이 느림, 실패인데 성공처럼 보임 | 7.3·8절: 처리 단계·busy·실패·미검사·출력 절단 구분 |

설치 완료 기록에는 사용한 압축본 해시, 이미지 ID, Compose 프로젝트명, 컨테이너 health, Open WebUI에서 조회한 두 도구, 실제 scan 응답 상태를 남깁니다. 토큰·검사 소스 원문은 넣지 않습니다. 신규 서버에서 아직 실행하지 않은 항목은 `UNVERIFIED`로 남깁니다.
