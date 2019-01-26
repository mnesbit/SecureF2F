@file:JvmName("Main")

package uk.co.nesbit

import org.apache.avro.Schema
import org.apache.avro.SchemaBuilder
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.network.api.Message
import uk.co.nesbit.network.api.NetworkAddress
import uk.co.nesbit.network.api.routing.RoutedMessage
import uk.co.nesbit.network.engineOld.Layer2Node
import uk.co.nesbit.network.engineOld.SimNetwork
import kotlin.concurrent.thread

data class TestMessage(val intField: Int) : Message {
    constructor(testRecord: GenericRecord) : this(testRecord.getTyped<Int>("intField"))

    companion object {
        val testSchema: Schema = SchemaBuilder.record("test1").fields().requiredInt("intField").endRecord()
    }

    override fun toGenericRecord(): GenericRecord {
        val testRecord = GenericData.Record(testSchema)
        testRecord.putTyped("intField", intField)
        return testRecord
    }
}

fun main(args: Array<String>) {
    println("Hello world")
    val network = SimNetwork()
    val net1 = network.getNetworkService(NetworkAddress(1))
    val net2 = network.getNetworkService(NetworkAddress(2))
    val net3 = network.getNetworkService(NetworkAddress(3))
    val node1 = Layer2Node(net1)
    val node2 = Layer2Node(net2)
    val node3 = Layer2Node(net3)
    net1.openLink(net2.networkId)
    net3.openLink(net2.networkId)
    var stopping = false
    node1.routeDiscoveryService.onReceive.subscribe {
        val received = TestMessage(TestMessage.testSchema.deserialize(it.payload))
        if (received.intField > 0) {
            val path = node1.routeDiscoveryService.findRandomRouteTo(it.replyTo)
            if (path != null) {
                node1.routeDiscoveryService.send(path, RoutedMessage.createRoutedMessage(node1.neighbourDiscoveryService.networkAddress, TestMessage(-received.intField)))
            }
        } else {
            println("1 received ${received.intField}")
        }
    }
    node3.routeDiscoveryService.onReceive.subscribe {
        val received = TestMessage(TestMessage.testSchema.deserialize(it.payload))
        if (received.intField > 0) {
            val path = node3.routeDiscoveryService.findRandomRouteTo(it.replyTo)
            if (path != null) {
                node3.routeDiscoveryService.send(path, RoutedMessage.createRoutedMessage(node3.neighbourDiscoveryService.networkAddress, TestMessage(-received.intField)))
            }
        } else {
            println("3 received ${received.intField}")
        }
    }
    val networkThread = thread {
        while (!stopping) {
            network.shuffleMessages()
            network.deliverTillEmpty()
            Thread.sleep(15)
        }
        network.deliverTillEmpty()
    }
    val node1Thread = thread {
        var sendId = 1
        while (!stopping) {
            node1.runStateMachine()
            val path = node1.routeDiscoveryService.findRandomRouteTo(node3.neighbourDiscoveryService.networkAddress)
            if (path != null) {
                println("1 send $sendId")
                node1.routeDiscoveryService.send(path, RoutedMessage.createRoutedMessage(node1.neighbourDiscoveryService.networkAddress, TestMessage(sendId++)))
            }
            val path2 = node3.routeDiscoveryService.findRandomRouteTo(node1.neighbourDiscoveryService.networkAddress)
            if (path2 != null) {
                println("3 send $sendId")
                node3.routeDiscoveryService.send(path2, RoutedMessage.createRoutedMessage(node3.neighbourDiscoveryService.networkAddress, TestMessage(sendId++)))
            }
            Thread.sleep(200)
        }
    }
    val node2Thread = thread {
        while (!stopping) {
            node2.runStateMachine()
            Thread.sleep(200)
        }
    }
    val node3Thread = thread {
        var sendId = 100000
        while (!stopping) {
            node3.runStateMachine()
            val path = node3.routeDiscoveryService.findRandomRouteTo(node1.neighbourDiscoveryService.networkAddress)
            if (path != null) {
                println("3 send $sendId")
                node3.routeDiscoveryService.send(path, RoutedMessage.createRoutedMessage(node3.neighbourDiscoveryService.networkAddress, TestMessage(sendId++)))
            }
            val path2 = node1.routeDiscoveryService.findRandomRouteTo(node3.neighbourDiscoveryService.networkAddress)
            if (path2 != null) {
                println("1 send $sendId")
                node1.routeDiscoveryService.send(path2, RoutedMessage.createRoutedMessage(node1.neighbourDiscoveryService.networkAddress, TestMessage(sendId++)))
            }
            Thread.sleep(200)
        }
    }
    System.`in`.read()
    stopping = true
    node1Thread.join()
    node3Thread.join()
    node2Thread.join()
    networkThread.join()
}
