import gleam/erlang/process.{type Subject}
import gleam/otp/actor
import voauth.{type RefreshError, type RefreshResponse}

pub opaque type Stub {
  Stub(subject: Subject(Message))
}

pub type Script =
  List(Result(RefreshResponse, RefreshError))

type Message {
  Next(
    reply: Subject(Result(RefreshResponse, RefreshError)),
    refresh_token: String,
  )
  Count(reply: Subject(Int))
}

type State {
  State(remaining: Script, count: Int)
}

pub fn start(script: Script) -> Stub {
  let assert Ok(started) =
    actor.new(State(remaining: script, count: 0))
    |> actor.on_message(handle)
    |> actor.start
  Stub(subject: started.data)
}

pub fn refresh_fn(stub: Stub) -> voauth.Refresh {
  let subject = stub.subject
  fn(rt: String) { process.call(subject, 1000, fn(reply) { Next(reply, rt) }) }
}

pub fn call_count(stub: Stub) -> Int {
  process.call(stub.subject, 1000, Count)
}

fn handle(state: State, message: Message) -> actor.Next(State, Message) {
  case message {
    Next(reply:, refresh_token: _) -> {
      case state.remaining {
        [head, ..tail] -> {
          process.send(reply, head)
          actor.continue(State(remaining: tail, count: state.count + 1))
        }
        [] -> panic as "voauth_stub: script exhausted, unexpected refresh call"
      }
    }
    Count(reply:) -> {
      process.send(reply, state.count)
      actor.continue(state)
    }
  }
}
