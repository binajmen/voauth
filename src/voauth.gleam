//// OAuth2 access-token vault with proactive refresh and bounded retry.
////
//// The vault holds the current access token, refreshes it before it
//// expires, retries transient failures, and gives up with a typed
//// error when the refresh token has been revoked. It does not perform
//// the OAuth flow itself; you provide a `Refresh` callback that talks
//// to your provider's token endpoint.
////
//// One vault per service. To handle multiple providers, start one
//// `Vault` per provider and supervise them with your application's
//// own supervisor.
////
//// A vault always starts without a token. Install one with `set_token`
//// after the user completes the OAuth flow, or after rehydrating from
//// durable storage at boot.
////
//// See the README for a quickstart.

import gleam/dynamic/decode
import gleam/erlang/process.{type Subject, type Timer}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/otp/actor
import gleam/otp/supervision
import gleam/result
import gleam/string
import logging

// =====================================================
// Public types
// =====================================================

/// A long-lived process holding the access token for one OAuth service.
/// Returned by `start`. Pass it through your application's context.
pub opaque type Vault {
  Vault(subject: Subject(Message), call_timeout_ms: Int)
}

/// Returned by a `Refresh` callback. The variant tells the vault
/// whether to retry the failure or give up. Application code can
/// pattern-match on `RefreshUnauthorized` to drive a "please
/// reconnect" UI.
pub type RefreshError {
  /// Transient failure — the vault will retry with backoff.
  /// Network drop, 5xx, timeout, parse error.
  RefreshRetryable(reason: String)

  /// The refresh token has been rejected. The user must reauthorise.
  /// OAuth2 `invalid_grant` / `invalid_token`, revoked credentials.
  RefreshUnauthorized(reason: String)
}

/// Returned by the public vault API.
pub type VaultError {
  /// The provider's `Refresh` callback returned an error.
  RefreshFailed(RefreshError)

  /// No token to refresh. Call `set_token` to install one, or check
  /// that your provider issued a `refresh_token` (some require an
  /// `offline_access` scope).
  NoRefreshToken

  /// The vault's actor failed to start. `reason` is the underlying
  /// failure description.
  StartError(reason: String)
}

/// An OAuth2 token as returned by an authorisation or refresh
/// endpoint. `expires_in` is in seconds, as on the wire.
pub type Token {
  Token(
    access_token: String,
    expires_in: Int,
    refresh_token: Option(String),
    scope: String,
    token_type: String,
  )
}

/// What an OAuth2 refresh endpoint may return. Per RFC 6749 §5.1/§6
/// only `access_token` is required; the rest are optional and carry
/// forward from the previous token via `merge_response`.
pub type RefreshResponse {
  RefreshResponse(
    access_token: String,
    expires_in: Option(Int),
    refresh_token: Option(String),
    scope: Option(String),
    token_type: Option(String),
  )
}

/// Provider-specific refresh-token grant. The vault calls this when
/// the cached token expires or a proactive refresh fires.
pub type Refresh =
  fn(String) -> Result(RefreshResponse, RefreshError)

/// Hook fired after every successful refresh, typically to persist
/// the new token. Errors are logged and otherwise ignored; the vault
/// keeps running.
pub type OnRefresh =
  fn(Token) -> Result(Nil, String)

/// Configuration for one vault.
///
/// Construct with `config(refresh:)` and tweak with the `with_*`
/// setters. The type is opaque so that future settings stay
/// non-breaking.
pub opaque type Config {
  Config(
    refresh: Refresh,
    on_refresh: Option(OnRefresh),
    call_timeout_ms: Int,
    init_timeout_ms: Int,
    refresh_at_percent: Int,
    min_refresh_delay_ms: Int,
    retry_backoff_ms: List(Int),
  )
}

// =====================================================
// Public API: Config builder
// =====================================================

/// Build a `Config` with defaults. The provider-specific `Refresh`
/// callback is the only required argument.
///
/// Defaults:
/// - `on_refresh`: `None`
/// - `call_timeout_ms`: 30_000 — must exceed worst-case `Refresh`
///   HTTP latency.
/// - `init_timeout_ms`: 1_000
/// - `refresh_at_percent`: 80 — proactive refresh at 80% of `expires_in`.
/// - `min_refresh_delay_ms`: 60_000 — floor on the proactive delay.
/// - `retry_backoff_ms`: `[30_000, 60_000, 120_000]` (30s/1m/2m).
pub fn config(refresh refresh: Refresh) -> Config {
  Config(
    refresh:,
    on_refresh: None,
    call_timeout_ms: 30_000,
    init_timeout_ms: 1000,
    refresh_at_percent: 80,
    min_refresh_delay_ms: 60_000,
    retry_backoff_ms: [30_000, 60_000, 120_000],
  )
}

/// Persist tokens after every successful refresh. Runs inside the
/// vault's mailbox; keep it fast.
pub fn with_on_refresh(config: Config, callback: OnRefresh) -> Config {
  Config(..config, on_refresh: Some(callback))
}

/// Timeout (ms) for synchronous calls into the vault. Must exceed
/// worst-case `Refresh` HTTP latency, because `get_token` blocks on
/// a refresh when the cached token has expired.
pub fn with_call_timeout_ms(config: Config, ms: Int) -> Config {
  Config(..config, call_timeout_ms: ms)
}

/// Timeout (ms) for the actor's initialise phase.
pub fn with_init_timeout_ms(config: Config, ms: Int) -> Config {
  Config(..config, init_timeout_ms: ms)
}

/// Proactive refresh fires at this percent of `expires_in`. Default 80.
pub fn with_refresh_at_percent(config: Config, percent: Int) -> Config {
  Config(..config, refresh_at_percent: percent)
}

/// Floor (ms) on the proactive delay. Guards against providers that
/// hand out very short `expires_in` values.
pub fn with_min_refresh_delay_ms(config: Config, ms: Int) -> Config {
  Config(..config, min_refresh_delay_ms: ms)
}

/// Backoff schedule for retrying a failed scheduled refresh, indexed
/// by failed-attempt number. `[]` disables retries.
pub fn with_retry_backoff_ms(config: Config, schedule: List(Int)) -> Config {
  Config(..config, retry_backoff_ms: schedule)
}

// =====================================================
// Decoders / merge helper
// =====================================================

/// Decoder for an OAuth2 token JSON object.
pub fn token_decoder() -> decode.Decoder(Token) {
  use access_token <- decode.field("access_token", decode.string)
  use expires_in <- decode.field("expires_in", decode.int)
  use refresh_token <- decode.field(
    "refresh_token",
    decode.optional(decode.string),
  )
  use scope <- decode.field("scope", decode.string)
  use token_type <- decode.field("token_type", decode.string)
  decode.success(Token(
    access_token:,
    expires_in:,
    refresh_token:,
    scope:,
    token_type:,
  ))
}

/// Decoder for a refresh response. Fields other than `access_token`
/// are optional per RFC 6749 §6 and decode to `None` when absent.
pub fn refresh_response_decoder() -> decode.Decoder(RefreshResponse) {
  use access_token <- decode.field("access_token", decode.string)
  use expires_in <- decode.optional_field(
    "expires_in",
    None,
    decode.optional(decode.int),
  )
  use refresh_token <- decode.optional_field(
    "refresh_token",
    None,
    decode.optional(decode.string),
  )
  use scope <- decode.optional_field(
    "scope",
    None,
    decode.optional(decode.string),
  )
  use token_type <- decode.optional_field(
    "token_type",
    None,
    decode.optional(decode.string),
  )
  decode.success(RefreshResponse(
    access_token:,
    expires_in:,
    refresh_token:,
    scope:,
    token_type:,
  ))
}

/// Merge a refresh response onto the previous token, carrying
/// forward any field the server omitted.
pub fn merge_response(previous: Token, resp: RefreshResponse) -> Token {
  Token(
    access_token: resp.access_token,
    expires_in: option.unwrap(resp.expires_in, previous.expires_in),
    refresh_token: option.or(resp.refresh_token, previous.refresh_token),
    scope: option.unwrap(resp.scope, previous.scope),
    token_type: option.unwrap(resp.token_type, previous.token_type),
  )
}

// =====================================================
// Public API: lifecycle
// =====================================================

/// Start a vault. The vault begins without a token; install one with
/// `set_token` before calling `get_token` or `refresh_now`.
pub fn start(config: Config) -> Result(Vault, VaultError) {
  do_start(config)
  |> result.map(fn(started) { started.data })
  |> result.map_error(fn(e) { StartError(string.inspect(e)) })
}

/// Build a child specification for a `gleam_otp` supervisor. On
/// restart the supervisor calls `start` with the same `config`. To
/// rehydrate a persisted token on restart, write your own
/// `supervision.worker` that reads from durable storage and calls
/// `start` and `set_token`.
pub fn supervised(config: Config) -> supervision.ChildSpecification(Vault) {
  supervision.worker(fn() { do_start(config) })
}

/// Return the current valid access token. Refreshes synchronously if
/// the cached token has expired. Returns `NoRefreshToken` if no token
/// has been installed yet.
pub fn get_token(vault: Vault) -> Result(String, VaultError) {
  process.call(vault.subject, vault.call_timeout_ms, GetToken)
}

/// Force a refresh now, regardless of remaining validity. Returns
/// `NoRefreshToken` if no token has been installed yet.
pub fn refresh_now(vault: Vault) -> Result(Nil, VaultError) {
  process.call(vault.subject, vault.call_timeout_ms, RefreshNow)
}

/// Install or replace the vault's token. Schedules a fresh proactive
/// refresh. Use it after the OAuth flow completes, or after a
/// re-authorisation hands you a new token.
pub fn set_token(vault: Vault, token: Token) -> Nil {
  process.call(vault.subject, vault.call_timeout_ms, fn(reply) {
    SetToken(reply, token)
  })
}

// =====================================================
// Internal: messages, state, dispatcher
// =====================================================

type Message {
  GetToken(reply: Subject(Result(String, VaultError)))
  RefreshNow(reply: Subject(Result(Nil, VaultError)))
  ScheduledRefresh(attempt: Int)
  SetToken(reply: Subject(Nil), token: Token)
}

type State {
  State(
    config: Config,
    token: Option(Token),
    created_at_ms: Int,
    expires_in_ms: Int,
    timer: Option(Timer),
    self: Subject(Message),
  )
}

fn do_start(config: Config) -> Result(actor.Started(Vault), actor.StartError) {
  let initialise = fn(self) {
    let state =
      State(
        config:,
        token: None,
        created_at_ms: 0,
        expires_in_ms: 0,
        timer: None,
        self:,
      )
    actor.initialised(state)
    |> actor.returning(Vault(self, config.call_timeout_ms))
    |> Ok
  }

  actor.new_with_initialiser(config.init_timeout_ms, initialise)
  |> actor.on_message(handle_message)
  |> actor.start
}

fn handle_message(state: State, message: Message) -> actor.Next(State, Message) {
  case message {
    GetToken(reply:) -> handle_get_token(reply, state)
    RefreshNow(reply:) -> handle_refresh_now(reply, state)
    ScheduledRefresh(attempt:) -> handle_scheduled_refresh(attempt, state)
    SetToken(reply:, token:) -> handle_set_token(reply, token, state)
  }
}

fn handle_get_token(
  reply: Subject(Result(String, VaultError)),
  state: State,
) -> actor.Next(State, Message) {
  case state.token {
    None -> {
      process.send(reply, Error(NoRefreshToken))
      actor.continue(state)
    }
    Some(token) -> {
      let elapsed = monotonic_ms() - state.created_at_ms
      case elapsed < state.expires_in_ms {
        True -> {
          process.send(reply, Ok(token.access_token))
          actor.continue(state)
        }
        False -> {
          let #(new_state, result) = attempt_refresh(state)
          let reply_value = case result {
            Ok(_) -> {
              let assert Some(t) = new_state.token
              Ok(t.access_token)
            }
            Error(err) -> Error(err)
          }
          process.send(reply, reply_value)
          actor.continue(new_state)
        }
      }
    }
  }
}

fn handle_refresh_now(
  reply: Subject(Result(Nil, VaultError)),
  state: State,
) -> actor.Next(State, Message) {
  case state.token {
    None -> {
      process.send(reply, Error(NoRefreshToken))
      actor.continue(state)
    }
    Some(_) -> {
      let #(new_state, result) = attempt_refresh(state)
      process.send(reply, result)
      actor.continue(new_state)
    }
  }
}

fn handle_scheduled_refresh(
  attempt: Int,
  state: State,
) -> actor.Next(State, Message) {
  // The timer that scheduled this message has fired; clear the
  // reference so `state.timer = Some(_)` always means "a timer is
  // pending".
  let state = State(..state, timer: None)
  case state.token {
    Some(_) -> {
      let #(new_state, result) = attempt_refresh(state)
      case result {
        Ok(_) -> actor.continue(new_state)
        Error(err) -> handle_refresh_failure(attempt, err, new_state)
      }
    }
    None -> actor.continue(state)
  }
}

fn handle_set_token(
  reply: Subject(Nil),
  token: Token,
  state: State,
) -> actor.Next(State, Message) {
  let state = cancel_timer_in_state(state)
  let timer = schedule_proactive(state.self, state.config, token.expires_in)
  let new_state =
    State(
      ..state,
      token: Some(token),
      created_at_ms: monotonic_ms(),
      expires_in_ms: token.expires_in * 1000,
      timer: Some(timer),
    )
  process.send(reply, Nil)
  actor.continue(new_state)
}

fn handle_refresh_failure(
  attempt: Int,
  err: VaultError,
  state: State,
) -> actor.Next(State, Message) {
  case err {
    RefreshFailed(RefreshUnauthorized(_)) | NoRefreshToken | StartError(_) -> {
      logging.log(
        logging.Warning,
        "voauth: refresh giving up (not retryable): " <> describe_error(err),
      )
      actor.continue(state)
    }
    RefreshFailed(RefreshRetryable(_)) ->
      case schedule_retry(state.self, state.config.retry_backoff_ms, attempt) {
        Some(timer) -> actor.continue(State(..state, timer: Some(timer)))
        None -> {
          logging.log(
            logging.Warning,
            "voauth: refresh giving up after "
              <> int.to_string(attempt + 1)
              <> " attempts: "
              <> describe_error(err),
          )
          actor.continue(state)
        }
      }
  }
}

// =====================================================
// Internal: refresh mechanics
// =====================================================

fn attempt_refresh(state: State) -> #(State, Result(Nil, VaultError)) {
  let state = cancel_timer_in_state(state)

  case state.token {
    Some(current_token) ->
      case current_token.refresh_token {
        Some(refresh_token) ->
          case state.config.refresh(refresh_token) {
            Ok(resp) -> {
              let token = merge_response(current_token, resp)
              case run_on_refresh(state.config, token) {
                Ok(Nil) -> Nil
                Error(reason) ->
                  logging.log(
                    logging.Error,
                    "voauth: on_refresh callback failed: " <> reason,
                  )
              }
              let timer =
                schedule_proactive(state.self, state.config, token.expires_in)
              let new_state =
                State(
                  ..state,
                  token: Some(token),
                  created_at_ms: monotonic_ms(),
                  expires_in_ms: token.expires_in * 1000,
                  timer: Some(timer),
                )
              #(new_state, Ok(Nil))
            }
            Error(refresh_error) -> #(
              state,
              Error(RefreshFailed(refresh_error)),
            )
          }
        None -> #(state, Error(NoRefreshToken))
      }
    None -> #(state, Error(NoRefreshToken))
  }
}

fn run_on_refresh(config: Config, token: Token) -> Result(Nil, String) {
  case config.on_refresh {
    None -> Ok(Nil)
    Some(callback) -> callback(token)
  }
}

fn describe_error(err: VaultError) -> String {
  case err {
    RefreshFailed(RefreshRetryable(reason)) -> "retryable: " <> reason
    RefreshFailed(RefreshUnauthorized(reason)) -> "unauthorized: " <> reason
    NoRefreshToken -> "no refresh token"
    StartError(reason) -> "vault start error: " <> reason
  }
}

// =====================================================
// Internal: timers
// =====================================================

/// Look up the backoff delay for the given failed-attempt number.
/// Returns `None` if the schedule is exhausted (caller should give up).
fn retry_backoff_at(schedule: List(Int), failed_attempt: Int) -> Option(Int) {
  schedule
  |> list.drop(failed_attempt)
  |> list.first
  |> option.from_result
}

fn schedule_proactive(
  self: Subject(Message),
  config: Config,
  expires_in_seconds: Int,
) -> Timer {
  let delay_ms = expires_in_seconds * 1000 * config.refresh_at_percent / 100
  let delay_ms = int.max(delay_ms, config.min_refresh_delay_ms)
  process.send_after(self, delay_ms, ScheduledRefresh(0))
}

/// Schedule the next retry attempt after a failed scheduled refresh.
/// Returns `None` if the backoff schedule is exhausted.
fn schedule_retry(
  self: Subject(Message),
  schedule: List(Int),
  failed_attempt: Int,
) -> Option(Timer) {
  case retry_backoff_at(schedule, failed_attempt) {
    Some(delay) ->
      Some(process.send_after(self, delay, ScheduledRefresh(failed_attempt + 1)))
    None -> None
  }
}

fn cancel_timer_in_state(state: State) -> State {
  case state.timer {
    Some(timer) -> {
      process.cancel_timer(timer)
      State(..state, timer: None)
    }
    None -> state
  }
}

@external(erlang, "voauth_ffi", "monotonic_ms")
fn monotonic_ms() -> Int
