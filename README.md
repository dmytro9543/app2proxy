# app2proxy

Version 1.5.7 adds IP2Location.io geolocation enrichment to proxy testing while preserving the existing backend request and response shape.

## Endpoints

### `POST /test-proxies-v1`

Legacy behavior. This is the original `/test-proxies` implementation and returns values such as:

```json
{
  "host:port:user:password": "203.0.113.10 (socks5-ipv4)"
}
```

### `POST /test-proxies`

Updated behavior. It accepts the exact same body and retains the same top-level `proxy -> string` response format, so the caller does not need to change its request handling.

Request:

```json
{
  "type": "any",
  "proxies": [
    "host:port:user:password"
  ]
}
```

Successful enriched response:

```json
{
  "host:port:user:password": "203.0.113.10 (socks5-ipv4) | Amsterdam, North Holland, Netherlands | ISP/AS: Example Network B.V. | ASN: 64500 | Geo: IP2Location.io"
}
```

The free IP2Location.io plan does not return the dedicated `isp` field. In that case the API uses the returned autonomous-system name and labels it `ISP/AS`. Paid responses containing `isp` are labeled `ISP`.

If IP2Location.io is unavailable, disabled, rate-limited, or returns an error, the proxy is still returned using the original value:

```json
{
  "host:port:user:password": "203.0.113.10 (socks5-ipv4)"
}
```

Offline and invalid values remain unchanged.

## Configuration

The integration supports the IP2Location.io keyless free API by default. For the registered free plan, set:

```bash
export IP2LOCATION_API_KEY='your-api-key'
```

To disable enrichment without changing the endpoint:

```bash
export IP2LOCATION_ENABLED=0
```

The provider URL defaults to `https://api.ip2location.io/`. `IP2LOCATION_API_URL` is available for controlled testing or an internal compatible gateway.

For systemd, add these values to the service environment or an `EnvironmentFile`, then restart `app2proxy`.

Results are cached in memory for 24 hours by exit IP to reduce quota usage. The cache is reset when the service restarts.

## Build

Dependencies include json-c, pthreads, and libcurl development headers.

```bash
make clean
make
```
