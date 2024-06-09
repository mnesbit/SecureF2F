package uk.co.nesbit.simpleactor.impl

import uk.co.nesbit.simpleactor.AbstractActor
import uk.co.nesbit.simpleactor.Props
import uk.co.nesbit.simpleactor.createProps

internal class RootActor : AbstractActor() {
    companion object {
        @JvmStatic
        fun getProps(): Props {
            return createProps(RootActor::class.java)
        }
    }

    override fun onReceive(message: Any) {
        context.log.warn("unexpected message of type ${message.javaClass.name} from $sender")
    }
}