package uk.co.nesbit.network.engine

import akka.actor.AbstractLoggingActor
import akka.actor.ActorRef
import akka.actor.Props
import akka.japi.pf.ReceiveBuilder
import uk.co.nesbit.network.api.routing.Routes

class LocalRoutesUpdate(val routes: Routes?)

class RouteDiscoveryActor(val neighbourLinkActor: ActorRef) : AbstractLoggingActor() {
    companion object {
        @JvmStatic
        fun getProps(neighbourLinkActor: ActorRef): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return Props.create(javaClass.enclosingClass, neighbourLinkActor)
        }
    }

    private var localRoutes: Routes? = null

    override fun preStart() {
        super.preStart()
        log().info("Starting RouteDiscoveryActor")
        neighbourLinkActor.tell(WatchRequest(), self)
    }

    override fun postStop() {
        super.postStop()
        log().info("Stopped RouteDiscoveryActor")
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        log().info("Restart RouteDiscoveryActor")
    }

    override fun createReceive(): Receive =
        ReceiveBuilder()
            .match(LocalRoutesUpdate::class.java, ::onLocalRoutesUpdate)
            .build()

    private fun onLocalRoutesUpdate(routes: LocalRoutesUpdate) {
        log().info("onLocalRoutesUpdate $routes")
        localRoutes = routes.routes
    }
}