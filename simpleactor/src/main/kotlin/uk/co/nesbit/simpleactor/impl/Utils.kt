package uk.co.nesbit.simpleactor.impl

import uk.co.nesbit.simpleactor.Actor
import uk.co.nesbit.simpleactor.ActorInitializationException
import java.lang.reflect.Constructor

@Suppress("UNCHECKED_CAST")
fun findActorConstructor(clazz: Class<*>, args: List<Any?>): Constructor<Actor> {
    return clazz.constructors.single { constructor ->
        constructor.parameterCount == args.size
                && constructor.parameterTypes.withIndex().all { indexed ->
            val arg = args[indexed.index]
            ((arg == null && !indexed.value.isPrimitive)
                    || (indexed.value.isInstance(arg)
                    || indexed.value.kotlin.javaObjectType.isInstance(arg))
                    )
        }
    } as Constructor<Actor>
}

fun createActorInstance(clazz: Class<*>, args: List<Any?>): Actor {
    try {
        val constructor = findActorConstructor(clazz, args)
        return constructor.newInstance(*(args.toTypedArray()))
    } catch (ex: Throwable) {
        throw ActorInitializationException("Unable to create actor of type ${clazz.name}", ex)
    }
}