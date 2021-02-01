package uk.co.nesbit.network

import akka.actor.ActorRef
import akka.actor.ActorSystem
import akka.testkit.TestActorRef
import akka.testkit.TestActors
import akka.testkit.TestKit
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import scala.jdk.javaapi.CollectionConverters
import uk.co.nesbit.network.api.*
import uk.co.nesbit.network.api.net.LinkReceivedMessage
import uk.co.nesbit.network.api.net.LinkSendMessage
import uk.co.nesbit.network.api.net.OpenRequest
import uk.co.nesbit.network.mocknet.*
import uk.co.nesbit.network.util.seconds

class NetworkTest {
    private var actorSystem: ActorSystem? = null

    @BeforeEach
    fun setup() {
        actorSystem = ActorSystem.create("Testing")
    }

    @AfterEach
    fun shutdown() {
        TestKit.shutdownActorSystem(actorSystem, 10.seconds(), true)
        actorSystem = null
    }

    @Test
    fun `Check initial registration with Dns`() {
        object : TestKit(actorSystem) {
            init {
                within(5.seconds()) {
                    // repoint /user/Dns to main test actor
                    actorSystem!!.actorOf(TestActors.forwardActorProps(testActor()), "Dns")
                    val config = NetworkConfiguration(NetworkAddress(1), NetworkAddress(1), false, setOf(), setOf())
                    // init basic actor
                    val physicalNetworkActor = actorSystem!!.actorOf(PhysicalNetworkActor.getProps(config))
                    // enable watch of any (unexpected) LinkInfo updates
                    physicalNetworkActor.tell(WatchRequest(), testActor())
                    // confirm tbe DNS query arrives
                    expectMsg(DnsRegistration(config.networkId as NetworkAddress))
                    // and then no more messages
                    expectNoMessage()
                }
            }
        }
    }

    @Test
    fun `Initiate active end connection`() {
        object : TestKit(actorSystem) {
            init {
                within(5.seconds()) {
                    // repoint /user/Dns to main test actor
                    val mockDns = actorSystem!!.actorOf(TestActors.forwardActorProps(testActor()), "Dns")
                    val config = NetworkConfiguration(NetworkAddress(1), NetworkAddress(1), false, setOf(), setOf())
                    // Make the actor in test mode, where we can access the object state
                    val physicalNetworkActor =
                            TestActorRef.create<PhysicalNetworkActor>(actorSystem, PhysicalNetworkActor.getProps(config))
                    // Register for LookInfo updates
                    physicalNetworkActor.tell(WatchRequest(), testActor())
                    // get automatic registration of DNS
                    expectMsg(DnsRegistration(config.networkId as NetworkAddress))
                    // kick off active link creation
                    physicalNetworkActor.tell(OpenRequest(NetworkAddress(2)), ActorRef.noSender())
                    // confirm onward DNS query
                    val dnsQuery = expectMsgClass(DnsLookup::class.java)
                    assertEquals(dnsQuery.networkId, NetworkAddress(2))
                    // send back a response with testActor as target
                    physicalNetworkActor.tell(DnsResponse(dnsQuery.linkId, testActor()), mockDns)
                    // confirm resulting direct connect request sent to the actor defined in the DNS reply(us)
                    val connectRequest = expectMsgClass(PhysicalNetworkActor.ConnectRequest::class.java)
                    assertEquals(connectRequest.sourceNetworkId, config.networkId)
                    // fake a positive reply
                    physicalNetworkActor.tell(
                            PhysicalNetworkActor.ConnectResult(connectRequest.linkId, true),
                            testActor()
                    )
                    // should get back update of new LinkInfo
                    val expectedLinkInfo = LinkInfo(
                            connectRequest.linkId,
                            Route(config.networkId, NetworkAddress(2)),
                            LinkStatus.LINK_UP_ACTIVE
                    )
                    expectMsg(expectedLinkInfo)
                    // but no more messages
                    expectNoMessage()
                    // At end of process state should be well defined
                    assertEquals(expectedLinkInfo, physicalNetworkActor.underlyingActor().links.values.single())
                    assertEquals(1, physicalNetworkActor.underlyingActor().targets.size)
                    assertEquals(testActor(), physicalNetworkActor.underlyingActor().targets[expectedLinkInfo.linkId])
                    assertEquals(0, physicalNetworkActor.underlyingActor().foreignLinks.size)
                }
            }
        }
    }

    @Test
    fun `Initiate passive end connection`() {
        object : TestKit(actorSystem) {
            init {
                within(5.seconds()) {
                    // repoint /user/Dns to main test actor
                    actorSystem!!.actorOf(TestActors.forwardActorProps(testActor()), "Dns")
                    val config = NetworkConfiguration(NetworkAddress(1), NetworkAddress(1), false, setOf(), setOf())
                    // Make the actor in test mode, where we can access the object state
                    val physicalNetworkActor =
                            TestActorRef.create<PhysicalNetworkActor>(actorSystem, PhysicalNetworkActor.getProps(config))
                    // Register for LookInfo updates
                    physicalNetworkActor.tell(WatchRequest(), testActor())
                    // get automatic registration of DNS
                    expectMsg(DnsRegistration(config.networkId as NetworkAddress))
                    // kick off passive link creation
                    val newLinkId = SimpleLinkId(100)
                    physicalNetworkActor.tell(
                            PhysicalNetworkActor.ConnectRequest(NetworkAddress(2), newLinkId),
                            testActor()
                    )
                    // Accepts connection
                    val connectResult = expectMsgClass(PhysicalNetworkActor.ConnectResult::class.java)
                    assertEquals(newLinkId, connectResult.linkId)
                    assertEquals(true, connectResult.opened)
                    // should get back update of new LinkInfo
                    val updateMessage = expectMsgClass(LinkInfo::class.java)
                    assertEquals(NetworkAddress(2), updateMessage.route.to)
                    assertEquals(config.networkId, updateMessage.route.from)
                    assertEquals(LinkStatus.LINK_UP_PASSIVE, updateMessage.status)
                    // but no more messages
                    expectNoMessage()
                    // At end of process state should be well defined
                    assertEquals(updateMessage, physicalNetworkActor.underlyingActor().links.values.single())
                    assertEquals(1, physicalNetworkActor.underlyingActor().targets.size)
                    assertEquals(testActor(), physicalNetworkActor.underlyingActor().targets[updateMessage.linkId])
                    assertEquals(1, physicalNetworkActor.underlyingActor().foreignLinks.size)
                    assertEquals(updateMessage.linkId, physicalNetworkActor.underlyingActor().foreignLinks[newLinkId])
                }
            }
        }
    }

    @Test
    fun `Shutdown active end connection via drop`() {
        object : TestKit(actorSystem) {
            init {
                within(5.seconds()) {
                    // repoint /user/Dns to main test actor
                    val mockDns = actorSystem!!.actorOf(TestActors.forwardActorProps(testActor()), "Dns")
                    val config = NetworkConfiguration(NetworkAddress(1), NetworkAddress(1), false, setOf(), setOf())
                    // Make the actor in test mode, where we can access the object state
                    val physicalNetworkActor =
                            TestActorRef.create<PhysicalNetworkActor>(actorSystem, PhysicalNetworkActor.getProps(config))
                    // Register for LookInfo updates
                    val mockWatcher = actorSystem!!.actorOf(TestActors.forwardActorProps(testActor()), "watcher")
                    physicalNetworkActor.tell(WatchRequest(), mockWatcher)
                    // get automatic registration of DNS
                    expectMsg(DnsRegistration(config.networkId as NetworkAddress))
                    // kick off active link creation
                    physicalNetworkActor.tell(OpenRequest(NetworkAddress(2)), ActorRef.noSender())
                    // confirm onward DNS query
                    val dnsQuery = expectMsgClass(DnsLookup::class.java)
                    val mockNode = actorSystem!!.actorOf(TestActors.forwardActorProps(testActor()), "node")
                    physicalNetworkActor.tell(DnsResponse(dnsQuery.linkId, mockNode), mockDns)
                    val connectRequest = expectMsgClass(PhysicalNetworkActor.ConnectRequest::class.java)
                    physicalNetworkActor.tell(
                            PhysicalNetworkActor.ConnectResult(connectRequest.linkId, true),
                            testActor()
                    )
                    val initialLinkUpMsg = expectMsgClass(LinkInfo::class.java)
                    assertEquals(LinkStatus.LINK_UP_ACTIVE, initialLinkUpMsg.status)
                    // drop the link
                    physicalNetworkActor.tell(
                            PhysicalNetworkActor.ConnectionDrop(connectRequest.linkId),
                            ActorRef.noSender()
                    )
                    // Expect down event passed to watcher
                    val linkDownMsg = expectMsgClass(LinkInfo::class.java)
                    assertEquals(initialLinkUpMsg.copy(status = LinkStatus.LINK_DOWN), linkDownMsg)
                    // At end of process state should be well defined
                    assertEquals(linkDownMsg, physicalNetworkActor.underlyingActor().links.values.single())
                    assertEquals(0, physicalNetworkActor.underlyingActor().targets.size)
                    assertEquals(0, physicalNetworkActor.underlyingActor().foreignLinks.size)
                    // subsequent terminate event should do nothing
                    actorSystem!!.stop(mockNode)
                    // but no more messages
                    expectNoMessage()
                }
            }
        }
    }

    @Test
    fun `Shutdown active end connection via process death`() {
        object : TestKit(actorSystem) {
            init {
                within(5.seconds()) {
                    // repoint /user/Dns to main test actor
                    val mockDns = actorSystem!!.actorOf(TestActors.forwardActorProps(testActor()), "Dns")
                    val config = NetworkConfiguration(NetworkAddress(1), NetworkAddress(1), false, setOf(), setOf())
                    // Make the actor in test mode, where we can access the object state
                    val physicalNetworkActor =
                            TestActorRef.create<PhysicalNetworkActor>(actorSystem, PhysicalNetworkActor.getProps(config))
                    // Register for LookInfo updates
                    val mockWatcher = actorSystem!!.actorOf(TestActors.forwardActorProps(testActor()), "watcher")
                    physicalNetworkActor.tell(WatchRequest(), mockWatcher)
                    // get automatic registration of DNS
                    expectMsg(DnsRegistration(config.networkId as NetworkAddress))
                    // kick off active link creation
                    physicalNetworkActor.tell(OpenRequest(NetworkAddress(2)), ActorRef.noSender())
                    // confirm onward DNS query and use proxy node
                    val dnsQuery = expectMsgClass(DnsLookup::class.java)
                    val mockNode = actorSystem!!.actorOf(TestActors.forwardActorProps(testActor()), "node")
                    physicalNetworkActor.tell(DnsResponse(dnsQuery.linkId, mockNode), mockDns)
                    val connectRequest = expectMsgClass(PhysicalNetworkActor.ConnectRequest::class.java)
                    physicalNetworkActor.tell(
                            PhysicalNetworkActor.ConnectResult(connectRequest.linkId, true),
                            testActor()
                    )
                    val initialLinkUpMsg = expectMsgClass(LinkInfo::class.java)
                    assertEquals(LinkStatus.LINK_UP_ACTIVE, initialLinkUpMsg.status)
                    // drop the link via signal of process death
                    actorSystem!!.stop(mockNode)
                    // Expect down event passed to watcher
                    val linkDownMsg = expectMsgClass(LinkInfo::class.java)
                    assertEquals(initialLinkUpMsg.copy(status = LinkStatus.LINK_DOWN), linkDownMsg)
                    // At end of process state should be well defined
                    assertEquals(linkDownMsg, physicalNetworkActor.underlyingActor().links.values.single())
                    assertEquals(0, physicalNetworkActor.underlyingActor().targets.size)
                    assertEquals(0, physicalNetworkActor.underlyingActor().foreignLinks.size)
                    // subsequent drop event should do nothing
                    physicalNetworkActor.tell(
                            PhysicalNetworkActor.ConnectionDrop(connectRequest.linkId),
                            ActorRef.noSender()
                    )
                    // but no more messages
                    expectNoMessage()
                }
            }
        }
    }

    @Test
    fun `Stop passive end connection via drop`() {
        object : TestKit(actorSystem) {
            init {
                within(5.seconds()) {
                    // repoint /user/Dns to main test actor
                    actorSystem!!.actorOf(TestActors.forwardActorProps(testActor()), "Dns")
                    val config = NetworkConfiguration(NetworkAddress(1), NetworkAddress(1), false, setOf(), setOf())
                    // Make the actor in test mode, where we can access the object state
                    val physicalNetworkActor =
                            TestActorRef.create<PhysicalNetworkActor>(actorSystem, PhysicalNetworkActor.getProps(config))
                    // Register for LookInfo updates
                    physicalNetworkActor.tell(WatchRequest(), testActor())
                    // get automatic registration of DNS
                    expectMsg(DnsRegistration(config.networkId as NetworkAddress))
                    // kick off passive link creation
                    val newLinkId = SimpleLinkId(100)
                    val mockNode = actorSystem!!.actorOf(TestActors.forwardActorProps(testActor()), "mockNode")
                    physicalNetworkActor.tell(
                            PhysicalNetworkActor.ConnectRequest(NetworkAddress(2), newLinkId),
                            mockNode
                    )
                    // should get back update of new LinkInfo
                    val msgs = CollectionConverters.asJava(receiveN(2))
                    val initialLinkUpMsg = msgs.single { it is LinkInfo } as LinkInfo
                    assertEquals(LinkStatus.LINK_UP_PASSIVE, initialLinkUpMsg.status)
                    val connectResult =
                            msgs.single { it is PhysicalNetworkActor.ConnectResult } as PhysicalNetworkActor.ConnectResult
                    assertEquals(true, connectResult.opened)
                    // drop the link
                    physicalNetworkActor.tell(PhysicalNetworkActor.ConnectionDrop(newLinkId), ActorRef.noSender())
                    // Expect down event passed to watcher
                    val linkDownMsg = expectMsgClass(LinkInfo::class.java)
                    assertEquals(initialLinkUpMsg.copy(status = LinkStatus.LINK_DOWN), linkDownMsg)
                    // At end of process state should be well defined
                    assertEquals(linkDownMsg, physicalNetworkActor.underlyingActor().links.values.single())
                    assertEquals(0, physicalNetworkActor.underlyingActor().targets.size)
                    assertEquals(0, physicalNetworkActor.underlyingActor().foreignLinks.size)
                    // subsequent terminate event should do nothing
                    actorSystem!!.stop(mockNode)
                    // but no more messages
                    expectNoMessage()
                }
            }
        }
    }

    @Test
    fun `Stop passive end connection via process death`() {
        object : TestKit(actorSystem) {
            init {
                within(5.seconds()) {
                    // repoint /user/Dns to main test actor
                    actorSystem!!.actorOf(TestActors.forwardActorProps(testActor()), "Dns")
                    val config = NetworkConfiguration(NetworkAddress(1), NetworkAddress(1), false, setOf(), setOf())
                    // Make the actor in test mode, where we can access the object state
                    val physicalNetworkActor =
                            TestActorRef.create<PhysicalNetworkActor>(actorSystem, PhysicalNetworkActor.getProps(config))
                    // Register for LookInfo updates
                    physicalNetworkActor.tell(WatchRequest(), testActor())
                    // get automatic registration of DNS
                    expectMsg(DnsRegistration(config.networkId as NetworkAddress))
                    // kick off passive link creation
                    val newLinkId = SimpleLinkId(100)
                    val mockNode = actorSystem!!.actorOf(TestActors.forwardActorProps(testActor()), "mockNode")
                    physicalNetworkActor.tell(
                            PhysicalNetworkActor.ConnectRequest(NetworkAddress(2), newLinkId),
                            mockNode
                    )
                    // should get back update of new LinkInfo
                    val msgs = CollectionConverters.asJava(receiveN(2))
                    val initialLinkUpMsg = msgs.single { it is LinkInfo } as LinkInfo
                    assertEquals(LinkStatus.LINK_UP_PASSIVE, initialLinkUpMsg.status)
                    val connectResult =
                            msgs.single { it is PhysicalNetworkActor.ConnectResult } as PhysicalNetworkActor.ConnectResult
                    assertEquals(true, connectResult.opened)
                    // drop the link via process death
                    actorSystem!!.stop(mockNode)
                    // Expect down event passed to watcher
                    val linkDownMsg = expectMsgClass(LinkInfo::class.java)
                    assertEquals(initialLinkUpMsg.copy(status = LinkStatus.LINK_DOWN), linkDownMsg)
                    // At end of process state should be well defined
                    assertEquals(linkDownMsg, physicalNetworkActor.underlyingActor().links.values.single())
                    assertEquals(0, physicalNetworkActor.underlyingActor().targets.size)
                    assertEquals(0, physicalNetworkActor.underlyingActor().foreignLinks.size)
                    // subsequent drop message should do nothing
                    physicalNetworkActor.tell(PhysicalNetworkActor.ConnectionDrop(newLinkId), ActorRef.noSender())
                    // but no more messages
                    expectNoMessage()
                }
            }
        }
    }

    @Test
    fun `Two network actors can communicate with each other two way`() {
        object : TestKit(actorSystem) {
            init {
                within(5.seconds()) {
                    // repoint /user/Dns to main test actor
                    actorSystem!!.actorOf(DnsMockActor.getProps(), "Dns")
                    val config1 = NetworkConfiguration(NetworkAddress(1), NetworkAddress(1), false, setOf(), setOf())
                    val config2 = NetworkConfiguration(NetworkAddress(2), NetworkAddress(2), false, setOf(), setOf())
                    // Make the actor in test mode, where we can access the object state
                    val physicalNetworkActor1 =
                            TestActorRef.create<PhysicalNetworkActor>(actorSystem, PhysicalNetworkActor.getProps(config1))
                    val physicalNetworkActor2 =
                            TestActorRef.create<PhysicalNetworkActor>(actorSystem, PhysicalNetworkActor.getProps(config2))
                    // Register for LookInfo updates
                    physicalNetworkActor1.tell(WatchRequest(), testActor())
                    physicalNetworkActor2.tell(WatchRequest(), testActor())
                    // Open link from 1 to 2
                    physicalNetworkActor1.tell(OpenRequest(config2.networkId), testActor())
                    val linkUpdate2 = expectMsgClass(LinkInfo::class.java)
                    assertEquals(LinkStatus.LINK_UP_PASSIVE, linkUpdate2.status)
                    val linkUpdate1 = expectMsgClass(LinkInfo::class.java)
                    assertEquals(LinkStatus.LINK_UP_ACTIVE, linkUpdate1.status)
                    // Send message from 1 to 2
                    physicalNetworkActor1.tell(
                        LinkSendMessage(
                            linkUpdate1.linkId,
                            "Hello1".toByteArray()
                        ), testActor()
                    )
                    val msg1 = expectMsgClass(LinkReceivedMessage::class.java)
                    assertEquals(linkUpdate2.linkId, msg1.linkId)
                    assertArrayEquals("Hello1".toByteArray(), msg1.msg)
                    // Send message from 2 to 1
                    physicalNetworkActor2.tell(
                        LinkSendMessage(
                            linkUpdate2.linkId,
                            "Hello2".toByteArray()
                        ), testActor()
                    )
                    val msg2 = expectMsgClass(LinkReceivedMessage::class.java)
                    assertEquals(linkUpdate1.linkId, msg2.linkId)
                    assertArrayEquals("Hello2".toByteArray(), msg2.msg)
                }
            }
        }
    }
}