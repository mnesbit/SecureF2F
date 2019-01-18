package uk.co.nesbit.network.engine

import akka.actor.AbstractLoggingActor
import akka.actor.ActorRef
import akka.actor.Props
import akka.japi.pf.ReceiveBuilder
import uk.co.nesbit.network.api.*
import java.util.concurrent.atomic.AtomicInteger

class PhysicalNetworkActor(val networkConfig: NetworkConfiguration) : AbstractLoggingActor() {
    companion object {
        @JvmStatic
        fun getProps(networkConfig: NetworkConfiguration): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return Props.create(javaClass.enclosingClass, networkConfig)
        }

        val linkIdCounter = AtomicInteger(0)
    }

    class StartNetwork
    data class ConnectRequest(val remoteNetworkId: NetworkAddress)
    data class ConnectResult(val remoteNetworkId: NetworkAddress, val opened: Boolean)

    val networkId get() = networkConfig.networkId
    val links = mutableMapOf<LinkId, Pair<LinkInfo, ActorRef>>()
    val addresses = mutableMapOf<Address, LinkId>()

    override fun preStart() {
        super.preStart()
        log().info("Starting PhysicalNetworkActor Actor")
        self.tell(StartNetwork(), ActorRef.noSender())
        context.actorSelection("/user/Dns").tell(DnsRegistration(networkId), self)
    }

    override fun postStop() {
        super.postStop()
        log().info("Stopped PhysicalNetworkActor Actor")
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        log().info("Restart PhysicalNetworkActor Actor")
    }

    override fun createReceive() =
        ReceiveBuilder()
            .match(StartNetwork::class.java) { onStart() }
            .match(DnsResponse::class.java, ::onDnsResponse)
            .match(ConnectRequest::class.java, ::onConnectRequest)
            .match(ConnectResult::class.java, ::onConnectResult)
            .build()

    private fun onStart() {
        log().info("Starting carrying out Dns lookup of static targets")
        val dns = context.actorSelection("/user/Dns")
        for (link in networkConfig.staticRoutes) {
            dns.tell(DnsLookup(link), self)
        }
    }

    private fun onDnsResponse(dnsResponse: DnsResponse) {
        log().info("got Dns response $dnsResponse")
        if (dnsResponse.actorRef == null) {
            log().error("Couldn't find Dns for ${dnsResponse.networkId}")
        } else {
            dnsResponse.actorRef.tell(ConnectRequest(networkId), self)
        }
    }

    private fun onConnectRequest(request: ConnectRequest) {
        log().info("got ConnectRequest $request")
        if (request.remoteNetworkId in networkConfig.blackListedSources) {
            sender.tell(ConnectResult(request.remoteNetworkId, false), ActorRef.noSender())
        } else {
            val linkid = SimpleLinkId(linkIdCounter.getAndIncrement())
            val linkInfo = LinkInfo(linkid, Route(networkId, request.remoteNetworkId), LinkStatus.LINK_UP_PASSIVE)
            links[linkid] = Pair(linkInfo, sender)
            addresses[request.remoteNetworkId] = linkid
            log().info("New LinkInfo $linkInfo")
            sender.tell(ConnectResult(request.remoteNetworkId, true), self)
        }
    }

    private fun onConnectResult(response: ConnectResult) {
        log().info("got ConnectResult $response")
        if (response.opened) {
            val linkid = SimpleLinkId(linkIdCounter.getAndIncrement())
            addresses[response.remoteNetworkId] = linkid
            val linkInfo = LinkInfo(linkid, Route(networkId, response.remoteNetworkId), LinkStatus.LINK_UP_PASSIVE)
            links[linkid] = Pair(linkInfo, sender)
            log().info("New LinkInfo $linkInfo")
        } else {
            log().error("Connection rejected $response")
        }
    }
}