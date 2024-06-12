package uk.co.nesbit.simpleactor

enum class SupervisorResponse {
    Escalate,
    Ignore,
    RestartChild,
    StopChild
}