package uk.co.nesbit.simpleactor

import com.typesafe.config.ConfigFactory
import org.junit.jupiter.api.Test
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

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
        val ref2 = system.actorOf(PollingActor.getProps(10000, ref1), "Test1")
        while (ref2.ask<Boolean>("Running").get()) {
            Thread.sleep(100L)
        }
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
}