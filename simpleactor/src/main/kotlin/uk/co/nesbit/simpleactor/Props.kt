package uk.co.nesbit.simpleactor

import java.lang.reflect.Modifier

data class Props(
    val clazz: Class<*>,
    val args: List<Any?>
) {
    companion object {
        fun create(clazz: Class<*>, args: List<Any?>): Props {
            require(
                Actor::class.java.isAssignableFrom(clazz)
                        && !Modifier.isAbstract(clazz.modifiers)
            ) {
                "Must be an non-abstract implementation of Actor"
            }
            return Props(clazz, args)
        }
    }
}

fun createProps(clazz: Class<*>, vararg args: Any?): Props {
    return Props.create(clazz, args.toList())
}