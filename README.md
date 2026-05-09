# voauth

OAuth2 access-token vault for Gleam. Proactive refresh, bounded retry,
typed errors.

## What's voauth?

When you call an OAuth2 API you have to renew the access token before
it expires. Done well, that needs a long-lived process holding the
current token, a timer to refresh before expiry, retry on transient
failures, and a way to tell the UI "the user has to reconnect" when
the refresh token gets revoked.

voauth is that process. You write the bit that talks to your
provider's `/oauth2/token` endpoint; voauth handles the rest.

## Installation

```sh
gleam add voauth
```

## Quickstart

```gleam
import gleam/option.{Some}
import voauth

pub fn main() {
  // 1. Build a config with sane defaults; override what you need.
  let config =
    voauth.config(refresh: my_refresh_function)
    |> voauth.with_on_refresh(my_persist_callback)

  // 2. Start the vault.
  let assert Ok(vault) = voauth.start(config)

  // 3. After OAuth (or rehydrating from your DB), install a token.
  voauth.set_token(vault, voauth.Token(
    access_token: "...",
    expires_in: 1800,
    refresh_token: Some("..."),
    scope: "...",
    token_type: "Bearer",
  ))

  // 4. Use the vault. Blocks until a valid access token is available
  //    (refreshes automatically if the cached one has expired).
  case voauth.get_token(vault) {
    Ok(token) -> // call your provider's API with `token`
    Error(voauth.RefreshFailed(voauth.RefreshUnauthorized(_))) ->
      // refresh token revoked — show "please reconnect" UI
    Error(voauth.RefreshFailed(voauth.RefreshRetryable(_))) ->
      // transient outage — caller may retry
    Error(voauth.NoRefreshToken) ->
      // no token installed yet — user hasn't authorised
    Error(voauth.StartError(_)) -> // vault start error
  }
}
```

## The `refresh` callback

Provider-specific. Performs the OAuth2 refresh-token grant and returns
either a `RefreshResponse` or a typed error:

```gleam
fn my_refresh_function(
  refresh_token: String,
) -> Result(voauth.RefreshResponse, voauth.RefreshError) {
  // ... HTTP call to your provider's /oauth2/token endpoint ...
  case status, body {
    200, body -> decode_refresh_response(body)

    // OAuth2 invalid_grant / invalid_token: refresh token is dead.
    400, body | 401, body if has_invalid_grant(body) ->
      Error(voauth.RefreshUnauthorized(body))

    // Everything else: treat as transient; voauth will retry with backoff.
    _, body -> Error(voauth.RefreshRetryable(body))
  }
}
```

Use `voauth.refresh_response_decoder()` for the JSON. voauth handles
the case where a provider omits fields like `scope` or `refresh_token`
on a refresh — `merge_response` carries the previous values forward.

## The `on_refresh` callback (optional)

Fired after every successful refresh. Use it to persist the new token
to durable storage (DB, file, secrets manager) so a process restart
can rehydrate from the latest state.

```gleam
fn my_persist_callback(token: voauth.Token) -> Result(Nil, String) {
  save_to_db(token)
}
```

The callback runs inside the vault's mailbox, so keep it fast. Errors
are logged at `Error` level via `logging` and otherwise ignored; the
vault keeps running.

## Configuration

`config(refresh:)` returns a `Config` with the defaults below. Override
with the `with_*` setters.

| Field | Default | Description |
|---|---|---|
| `on_refresh` | `None` | Persistence hook. |
| `call_timeout_ms` | `30_000` | Caller-side timeout for `get_token` / `refresh_now` / `set_token`. Must exceed worst-case `refresh` HTTP latency. |
| `init_timeout_ms` | `1_000` | Actor initialisation timeout. |
| `refresh_at_percent` | `80` | Proactive refresh fires at this percent of `expires_in`. |
| `min_refresh_delay_ms` | `60_000` | Floor on the proactive delay. |
| `retry_backoff_ms` | `[30_000, 60_000, 120_000]` | Backoff schedule for failed scheduled refreshes. `[]` disables retries. |

## Crash recovery

The vault actor can be supervised by your application's `gleam_otp`
supervisor. `voauth.supervised(config)` returns a child specification.
On restart the supervisor calls `start(config)` with the same config.

To survive a full BEAM restart, persist tokens via `on_refresh` and
re-install via `set_token` from your durable store on application
startup. voauth doesn't own a persistence backend.

## Errors

- `RefreshFailed(RefreshRetryable(_))` — transient; voauth retries
  with backoff.
- `RefreshFailed(RefreshUnauthorized(_))` — refresh token rejected;
  user must reauthorise.
- `NoRefreshToken` — no token installed yet, or the installed token
  has no `refresh_token`.
- `StartError(_)` — vault failed to start.

## Development

```sh
gleam test
```
