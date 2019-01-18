package uk.co.nesbit.network.example

import akka.actor.ActorRef
import akka.actor.ActorSystem
import akka.pattern.Patterns.gracefulStop
import java.time.Duration
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

class Node(val name: String) {
    val lock = ReentrantLock()
    var actorSystem: ActorSystem? = null
    var rootActor: ActorRef? = null

    fun start() {
        lock.withLock {
            if (actorSystem != null) {
                return
            }
            actorSystem = ActorSystem.create(name)
            rootActor = actorSystem!!.actorOf(SimpleActor.getProps(), "actor1")
        }
    }

    fun stop() {
        lock.withLock {
            gracefulStop(rootActor, Duration.ofSeconds(5), "DIE")
            rootActor = null
            actorSystem?.terminate()?.value()
            actorSystem = null
        }

    }

    fun push(msg: String) {
        rootActor!!.tell(msg, ActorRef.noSender())
    }
}