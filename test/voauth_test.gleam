import gleam/erlang/process
import gleam/option.{None, Some}
import gleeunit
import voauth.{
  type Config, type RefreshError, type RefreshResponse, type Token, type Vault,
  NoRefreshToken, RefreshResponse, RefreshRetryable, RefreshUnauthorized, Token,
}
import voauth_stub.{type Stub}

pub fn main() -> Nil {
  gleeunit.main()
}

// =====================================================
// Helpers
// =====================================================

fn make_token(expires_in: Int) -> Token {
  Token(
    access_token: "access-v1",
    expires_in:,
    refresh_token: Some("rt-1"),
    scope: "read",
    token_type: "Bearer",
  )
}

fn ok_resp(access: String) -> Result(RefreshResponse, RefreshError) {
  Ok(RefreshResponse(
    access_token: access,
    expires_in: Some(60),
    refresh_token: Some("rt-1"),
    scope: None,
    token_type: None,
  ))
}

fn retryable() -> Result(RefreshResponse, RefreshError) {
  Error(RefreshRetryable("net"))
}

fn unauthorized() -> Result(RefreshResponse, RefreshError) {
  Error(RefreshUnauthorized("invalid_grant"))
}

fn make_vault(
  script: voauth_stub.Script,
  tweaks: fn(Config) -> Config,
) -> #(Vault, Stub) {
  let stub = voauth_stub.start(script)
  let cfg =
    voauth.config(refresh: voauth_stub.refresh_fn(stub))
    |> voauth.with_call_timeout_ms(500)
    |> voauth.with_init_timeout_ms(500)
    |> tweaks
  let assert Ok(v) = voauth.start(cfg)
  #(v, stub)
}

fn aggressive_proactive(cfg: Config) -> Config {
  cfg
  |> voauth.with_min_refresh_delay_ms(20)
  |> voauth.with_refresh_at_percent(1)
  |> voauth.with_retry_backoff_ms([10, 20])
}

// =====================================================
// Tests
// =====================================================

pub fn happy_path_get_token_returns_cached_test() {
  let #(v, stub) = make_vault([], fn(c) { c })
  voauth.set_token(v, make_token(60))
  assert voauth.get_token(v) == Ok("access-v1")
  assert voauth_stub.call_count(stub) == 0
}

pub fn get_token_refreshes_when_expired_test() {
  let #(v, stub) =
    make_vault([ok_resp("access-v2")], fn(c) {
      c |> voauth.with_min_refresh_delay_ms(10_000)
    })
  voauth.set_token(v, make_token(0))
  assert voauth.get_token(v) == Ok("access-v2")
  assert voauth_stub.call_count(stub) == 1
}

pub fn proactive_refresh_retries_then_succeeds_test() {
  let #(v, stub) =
    make_vault([retryable(), ok_resp("access-v2")], aggressive_proactive)
  voauth.set_token(v, make_token(1))
  process.sleep(80)
  assert voauth_stub.call_count(stub) == 2
  assert voauth.get_token(v) == Ok("access-v2")
}

pub fn proactive_refresh_exhausts_retry_schedule_test() {
  let #(v, stub) =
    make_vault([retryable(), retryable(), retryable()], aggressive_proactive)
  voauth.set_token(v, make_token(1))
  process.sleep(120)
  assert voauth_stub.call_count(stub) == 3
  assert voauth.get_token(v) == Ok("access-v1")
}

pub fn unauthorized_skips_retries_test() {
  let #(v, stub) = make_vault([unauthorized()], aggressive_proactive)
  voauth.set_token(v, make_token(1))
  process.sleep(80)
  assert voauth_stub.call_count(stub) == 1
  assert voauth.get_token(v) == Ok("access-v1")
}

pub fn on_refresh_callback_fires_on_success_test() {
  let captured = process.new_subject()
  let #(v, _stub) =
    make_vault([ok_resp("access-v2")], fn(c) {
      c
      |> aggressive_proactive
      |> voauth.with_on_refresh(fn(t) {
        process.send(captured, t)
        Ok(Nil)
      })
    })
  voauth.set_token(v, make_token(1))
  let assert Ok(token) = process.receive(captured, 200)
  assert token.access_token == "access-v2"
  assert token.refresh_token == Some("rt-1")
}

pub fn on_refresh_callback_failure_does_not_crash_test() {
  let #(v, stub) =
    make_vault([ok_resp("access-v2")], fn(c) {
      c
      |> aggressive_proactive
      |> voauth.with_on_refresh(fn(_) { Error("boom") })
    })
  voauth.set_token(v, make_token(1))
  process.sleep(60)
  assert voauth_stub.call_count(stub) == 1
  assert voauth.get_token(v) == Ok("access-v2")
}

pub fn get_token_before_set_token_returns_no_refresh_token_test() {
  let #(v, stub) = make_vault([], fn(c) { c })
  assert voauth.get_token(v) == Error(NoRefreshToken)
  assert voauth.refresh_now(v) == Error(NoRefreshToken)
  assert voauth_stub.call_count(stub) == 0
}
