# 폐쇄망 배포

연결망 빌드 PC에서 `WHEELHOUSE_DIR`에 Linux amd64/Python 3.12 wheel만 준비하고 다음을 실행합니다.

```bash
WHEELHOUSE_DIR=/path/to/wheelhouse scripts/build_airgap.sh dist
```

스크립트는 외부 네트워크 없이 Docker build를 수행하고 image tar, compose/Nginx/config example, provenance, lock, license 고지와 SHA-256 목록을 하나의 tar.gz로 만듭니다. 실제 token, token digest, TLS private key는 산출물에 넣지 않습니다.

전송 전 연결망 빌드 PC에서 bundle verifier를 실행합니다. 생성된 tar.gz는 로컬 배포 산출물이며 소스 저장소에는 커밋하지 않습니다.

```bash
scripts/verify_airgap.sh koda-mcp-security-0.1.0-linux-amd64.tar.gz
```

폐쇄망 서버에서는 압축을 푼 디렉터리에서 checksum을 확인하고 image를 load합니다. 실제 설정 파일은 UID/GID `10001:10001` 소유의 mode `0400` regular file로 별도 배치합니다.

```bash
cd koda-mcp-security-0.1.0-linux-amd64
sha256sum -c metadata/SHA256SUMS
docker load -i image/koda-mcp-security-0.1.0-amd64.tar
chown 10001:10001 /run/secrets/koda_mcp.json
chmod 0400 /run/secrets/koda_mcp.json
KODA_MCP_CONFIG_PATH=/run/secrets/koda_mcp.json docker compose -f deploy/compose.yaml up -d
```

Continue direct MCP와 Open WebUI 선택 MCP는 각각 별도 KODA bearer token을 사용합니다. 두 경로를 모두 활성화하지 않았다면 사용하지 않은 경로는 검증 대상이 아닙니다.

호스트 Nginx 적용 전 `nginx -t`를 통과시킵니다. 적용 후에는 올바른 내부 CA와 FQDN으로 `/mcp`가 연결되고 `/healthz`와 다른 경로는 404인지 확인하며, 잘못된 CA와 hostname 연결은 반드시 실패해야 합니다. 인증서·CA·FQDN이 제공되지 않은 상태에서는 TLS 검증을 완료로 표시하지 않습니다.
