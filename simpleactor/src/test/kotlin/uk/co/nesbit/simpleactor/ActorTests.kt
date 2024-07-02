package uk.co.nesbit.simpleactor

import com.typesafe.config.ConfigFactory
import org.junit.jupiter.api.Test
import uk.co.nesbit.simpleactor.impl.messages.Watch
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class ActorTests {
    @Test
    fun `simple actor creation, restart and shutdown deadlock test`() {
        val conf = ConfigFactory.parseString(
            """
                SimpleActor {
                        executor {
                                type = Single // Validate things won't deadlock
                        }
                }
        """
        )
        val system = ActorSystem.create("Test", conf)
        val ref1 = system.actorOf(MinimumTestActorInt.getProps(1), "Int")
        assertEquals("SimpleActor://Test/Int", ref1.path.address)
        val ref2 = ref1.ask<ActorRef>("CreateChildString").get()
        assertEquals("SimpleActor://Test/Int/String", ref2.path.address)
        val ref2b = ref1.ask<ActorRef>("CreateChildObj").get()
        assertEquals("SimpleActor://Test/Int/Obj", ref2b.path.address)
        assertEquals(1, ref1.ask<Int>("Get").get())
        ref1.tell(2)
        assertEquals(2, ref1.ask<Int>("Get").get())
        ref1.tell("Unhandled") //force restart
        assertEquals(1, ref1.ask<Int>("Get").get()) // read original value after restart
        val ref3 = system.actorOf(MinimumTestActorObj.getProps(null), "Null")
        assertEquals("SimpleActor://Test/Null", ref3.path.address)
        val ref4 = system.actorOf(MinimumTestActorObj.getProps(Thing(2)), "Thing")
        assertEquals("SimpleActor://Test/Thing", ref4.path.address)
        system.stop()
    }

    @Test
    fun `simple actor creation, restart and shutdown`() {
        val conf = ConfigFactory.parseString(
            """
                SimpleActor {
                }
        """
        )
        val system = ActorSystem.create("Test", conf)
        val ref1 = system.actorOf(MinimumTestActorInt.getProps(1), "Int")
        assertEquals("SimpleActor://Test/Int", ref1.path.address)
        val ref2 = ref1.ask<ActorRef>("CreateChildString").get()
        assertEquals("SimpleActor://Test/Int/String", ref2.path.address)
        val ref2b = ref1.ask<ActorRef>("CreateChildObj").get()
        assertEquals("SimpleActor://Test/Int/Obj", ref2b.path.address)
        assertEquals(1, ref1.ask<Int>("Get").get())
        ref1.tell(2)
        assertEquals(2, ref1.ask<Int>("Get").get())
        ref1.tell("Unhandled") //force restart
        assertEquals(1, ref1.ask<Int>("Get").get()) // read original value after restart
        val ref3 = system.actorOf(MinimumTestActorObj.getProps(null), "Null")
        assertEquals("SimpleActor://Test/Null", ref3.path.address)
        val ref4 = system.actorOf(MinimumTestActorObj.getProps(Thing(2)), "Thing")
        assertEquals("SimpleActor://Test/Thing", ref4.path.address)
        system.stop()
    }

    @Test
    fun `pump messages`() {
        val conf = ConfigFactory.parseString(
            """
                SimpleActor {
                }
        """
        )
        val system = ActorSystem.create("Test", conf)
        val ref1 = system.actorOf(MinimumTestActorInt.getProps(1), "Int")
        assertEquals("SimpleActor://Test/Int", ref1.path.address)
        val numItems = 100000
        for (i in 0 until numItems) {
            ref1.tell(i)
            if (i % 1000 == 0) {
                assertEquals(i, ref1.ask<Int>("Get").get())
            }
        }
        assertEquals(numItems - 1, ref1.ask<Int>("Get").get())
        system.stop()
    }

    @Test
    fun `pump messages 2`() {
        val conf = ConfigFactory.parseString(
            """
                SimpleActor {
                }
        """
        )
        val system = ActorSystem.create("Test", conf)
        val ref1 = system.actorOf(MinimumTestActorInt.getProps(1), "Int")
        assertEquals("SimpleActor://Test/Int", ref1.path.address)
        val ref2 = system.actorOf(PollingActor.getProps(1000, ref1), "Test1")
        while (ref2.ask<Boolean>("Running").get()) {
            Thread.sleep(100L)
        }
        system.stop(ref1)
        system.stop(ref2)
        system.stop()
    }

    @Test
    fun `pump messages 3`() {
        val conf = ConfigFactory.parseString(
            """
                SimpleActor {
                    executor {
                        type = Fixed
                        threads = 10
                    }
                    mailbox {
                        batchMaxUS = 100
                    }
                }
        """
        )
        val system = ActorSystem.create("Test", conf)
        val ref1 = system.actorOf(MinimumTestActorInt.getProps(1), "Int")
        assertEquals("SimpleActor://Test/Int", ref1.path.address)
        val ref2 = system.actorOf(PollingActor.getProps(1000, ref1), "Test1")
        while (ref2.ask<Boolean>("Running").get()) {
            Thread.sleep(100L)
        }
        system.stop(ref1)
        system.stop(ref2)
        system.stop()
    }

    @Test
    fun `stop test`() {
        val conf = ConfigFactory.parseString(
            """
                SimpleActor {
                }
        """
        )
        val system = ActorSystem.create("Test", conf)
        val ref1 = system.actorOf(MinimumTestActorInt.getProps(1), "Int")
        assertEquals("SimpleActor://Test/Int", ref1.path.address)
        ref1.tell("CreateChildInt")
        ref1.ask<String>("StopChild").get()
        ref1.tell("CreateChildInt")
        ref1.ask<String>("StopChild2").get()
        system.stop()
    }

    @Test
    fun `send to invalid ref`() {
        val conf = ConfigFactory.parseString(
            """
                SimpleActor {
                }
        """
        )
        val system = ActorSystem.create("Test", conf)
        val ref1 = system.actorOf(MinimumTestActorInt.getProps(1), "Int")
        assertEquals(1, ref1.ask<Int>("Get").get())
        ref1.tell(PoisonPill) // Stop actor
        assertFailsWith<TimeoutException> {
            ref1.ask<Int>("Get").get(100L, TimeUnit.MILLISECONDS)
        }
        system.stop()
    }

    @Test
    fun `timer tests`() {
        val conf = ConfigFactory.parseString(
            """
                SimpleActor {
                }
        """
        )
        val system = ActorSystem.create("Test", conf)
        val ref1 = system.actorOf(TimerTestActor.getProps(20), "TimerActor")
        while (ref1.ask<Int>("Get").get() != 0) {
            Thread.sleep(100L)
        }
        system.stop(ref1)
        system.stop()
    }

    @Test
    fun `create child actor inside construction`() {
        val conf = ConfigFactory.parseString(
            """
                SimpleActor {
                }
        """
        )
        val system = ActorSystem.create("Test", conf)
        for (i in 0 until 100) {
            system.actorOf(RecursiveActor.getProps(10), "Recursive_$i")
        }
        for (i in 0 until 100) {
            var path = "/Recursive_$i"
            val ref = system.actorSelection(path).resolve().single()
            println("test $path")
            assertEquals("SimpleActor://Test$path", ref.ask<String>("Test$i").get())
            for (level in 9 downTo 0) {
                path += "/$level"
                val ref2 = system.actorSelection(path).resolve().single()
                println("test $path")
                assertEquals("SimpleActor://Test$path", ref2.ask<String>("Test$i.level.$level").get())
            }

        }
        system.stop()
    }

    @Test
    fun `ActorSelector test`() {
        val conf = ConfigFactory.parseString(
            """
                SimpleActor {
                }
        """
        )
        val system = ActorSystem.create("Test", conf)
        for (i in 0 until 100) {
            system.actorOf(RecursiveActor.getProps(10), "Recursive_$i")
        }

        val addresses1 = system.actorSelection("/*15").resolve().map { it.path.address }.toSet()
        assertEquals(setOf("SimpleActor://Test/Recursive_15"), addresses1)
        val addresses2 = system.actorSelection("/*19/*/*/*").resolve().map { it.path.address }.toSet()
        assertEquals(
            setOf("SimpleActor://Test/Recursive_19/9/8/7", "SimpleActor://Test/Recursive_19/9/8/sibling"),
            addresses2
        )
        val addresses3 = system.actorSelection("/Recursive_*/*/*").resolve().map { it.path.address }.toSet()
        assertEquals((0..99).flatMap {
            listOf(
                "SimpleActor://Test/Recursive_$it/9/8",
                "SimpleActor://Test/Recursive_$it/9/sibling"
            )
        }.toSet(), addresses3)
        val addresses4 = system.actorSelection("/Recursive_?5/*/*").resolve().map { it.path.address }.toSet()
        assertEquals((1..9).flatMap {
            listOf(
                "SimpleActor://Test/Recursive_${it}5/9/8",
                "SimpleActor://Test/Recursive_${it}5/9/sibling"
            )
        }.toSet(), addresses4)
        val addresses5 = system.actorSelection("/Recursive_11/../*").resolve().map { it.path.address }.toSet()
        assertEquals((0..99).map { "SimpleActor://Test/Recursive_${it}" }.toSet(), addresses5)
        val tester = system.actorSelection("/Recursive_5/9/8/7/6/5").resolve().single()
        val resolvedFromChild = tester.ask<ActorSelection>("Select:*").get().resolve().map { it.path.address }.toSet()
        assertEquals(
            setOf(
                "SimpleActor://Test/Recursive_5/9/8/7/6/5/4",
                "SimpleActor://Test/Recursive_5/9/8/7/6/5/sibling"
            ), resolvedFromChild
        )
        val resolvedFromChild2 =
            tester.ask<ActorSelection>("Select:/Recursive_3/9").get().resolve().map { it.path.address }.toSet()
        assertEquals(setOf("SimpleActor://Test/Recursive_3/9"), resolvedFromChild2)
        system.stop()
    }

    @Test
    fun `supervisor tests`() {
        val conf = ConfigFactory.parseString(
            """
                SimpleActor {
                }
        """
        )
        val system = ActorSystem.create("Test", conf)
        val events = ArrayBlockingQueue<Any>(10)
        val watcher = system.createMessageSink { _, msg, _ ->
            events.add(msg)
        }
        val grandParent = system.actorOf(GrandSupervisorActor.getProps())
        assertEquals("Pong_0", grandParent.ask<String>("Ping").get())
        grandParent.tell(Watch(grandParent, watcher), watcher)
        val parent = grandParent.ask<ActorRef>("CreateChild").get()
        assertEquals("Pong_0", parent.ask<String>("Ping").get())
        parent.tell(Watch(parent, watcher), watcher)
        val child = parent.ask<ActorRef>("CreateChild").get()
        child.tell(Watch(child, watcher), watcher)
        assertEquals("Pong_0", child.ask<String>("Ping").get())
        assertEquals(true, events.isEmpty())
        child.tell("Ignore")
        assertEquals("Pong_1", child.ask<String>("Ping").get())
        child.tell("Restart")
        assertEquals(true, events.isEmpty())
        assertEquals("Pong_0", child.ask<String>("Ping").get()) //count reset on re-create
        child.tell("Stop")
        assertEquals(Terminated(child), events.take())
        assertEquals(true, events.isEmpty())
        assertFailsWith<TimeoutException> { child.ask<String>("Ping").get(100L, TimeUnit.MILLISECONDS) }
        val child2 = parent.ask<ActorRef>("CreateChild").get()
        assertNotEquals(child, child2)
        child2.tell(Watch(child2, watcher), watcher)
        assertEquals("Pong_0", child2.ask<String>("Ping").get())
        child2.tell("Escalate")
        assertEquals(Terminated(child2), events.take())
        assertEquals(Terminated(parent), events.take())
        assertEquals(true, events.isEmpty())
        val parent2 = grandParent.ask<ActorRef>("CreateChild").get()
        parent2.tell(Watch(parent2, watcher), watcher)
        val child3 = parent2.ask<ActorRef>("CreateChild").get()
        child3.tell(Watch(child3, watcher), watcher)
        assertEquals("Pong_0", child3.ask<String>("Ping").get())
        assertEquals("Pong_1", child3.ask<String>("Ping").get())
        child3.tell("Escalate2")
        assertEquals(Terminated(child3), events.take())
        assertEquals(Terminated(parent2), events.take())
        assertEquals(true, events.isEmpty())
        assertEquals("Pong_0", grandParent.ask<String>("Ping").get())
        grandParent.tell(Kill, Actor.NoSender)
        assertEquals(Terminated(grandParent), events.take())
        assertEquals(true, events.isEmpty())
        watcher.close()
        system.stop()
    }
}