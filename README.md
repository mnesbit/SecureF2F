# A secure Friend-to-Friend network experiment

## Introduction

This project is my exploration of a series of ideas for designing a secure self-organizing Friend-to-Friend network,
similar in principle to [IPFS](https://docs.ipfs.tech/),
or [Yggdrasil](https://github.com/yggdrasil-network/yggdrasil-go). Unlike a Peer-to-Peer network, arbitrary nodes cannot
directly link to each other, but must multi-hop route across links between nodes that know each other. This matches my
own experience of trying to form financial business-to-business networks, which was impeded by policies preventing
arbitrary node connectivity.

The ultimate goal is to support a full set of P2P service primitives, specifically: peer discovery; secure end-to-end
encryption; DHT storage; forward secure group key management; TCP-like reliable streaming and distributed atomic commit.
Currently, only peer discovery, end-to-end encryption, DHT storage and reliable streaming are implemented.

## Influences

The work is very heavily influenced by the papers of Stefanie Roos's research group particularly those of Martin
Byrenheid on a secure spanning tree
construction ([Byrenheid, M. , Roos, M. and Strufe, T., 2019](https://arxiv.org/pdf/1901.02729) and the subsequent
enhancement
papers [Byrenheid, M., Strufe, T. and Roos, S., 2020](https://ieeexplore.ieee.org/abstract/document/9252048) [Byrenheid, M., Roos, S., and Strufe, T., 2022](https://dl.acm.org/doi/abs/10.1145/3491003.3491020).

I have also used George Danezis's Sphinx
protocol [Danezis, G. and Goldberg, I., 2009](https://cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf) (with AED
encryption ideas
from [Beato, Filipe, Kimmo Halunen, and Mennink, 2016](https://bib.mixnetworks.org/pdf/beato2016improving.pdf)) as the
multi-hop encryption approach for data once the routes have been established over the Greedy Routing layer of the
spanning tree.

## The Protocol

The system is built using an asynchronous Actor framework as a series of layers.

### Inter-Node Transport Layer

The lowest layer is the physical transport layer. This involves hosting a client manager for initiating outbound links
and optionally an advertised server endpoint for inbound connections. It is imagined that ultimately some nodes would
act as public gateways, whilst many others would only allow strictly private, IP firewalled, interconnects to friendly
peers over VPN's, MPLS, etc. Currently, simple In-Memory, TCP and HTTPS modes are implemented.

The Actor model uses an `OpenRequest` messages from upper layers to attempt to initiate a link. On successful
establishment of channel a `LinkInfo` message is sent to the upper layers at each end, assigning a unique `LinkId` to
the bi-directional channel. If the channel is lost for any reason a closing `LinkInfo` will be sent. The upper layers
may close the channel using `CloseRequest`, or `CloseAllRequest` messages. For transports that do not have durable
sessions (e.g. HTTPS) a virtual `LinkId` needs to be added to allow upper levels to identify expected packet origins.

Assuming the `LinkStatus` is active, application data messages may be sent to the peer using `LinkSendMessage` and
received packets are wrapped into `LinkReceivedMessage` packets. The underlying channel is not required to encrypt the
packets, although it may e.g. in HTTPS, so the payloads are assumed to already be encrypted.

### Spanning Tree Based Global Network

This layer opens links to the configured neighbour nodes and then establishes secure, but anonymised paths to the rest
of the network.

Each node creates a `SphinxIdentityKeyPair` at start up. This contains a Diffie-Hellman X25519 key pair and an EdDSA
signing key pair. It also contains a signed hash chain calculated using HMAC over the public keys and embedded public
address string. Calculating this hash chain is partly intended to rate limit mining for new identities. It also puts
limits on the lifespan of an identity as periodically earlier version hashes must be revealed in the protocol and thus
tree roots are required to relinquish control after a while.

When a link is established a `Hello` is sent containing the node's public `VersionedIdentity` and a random Nonce, signed
over with the associated private signing key. This allows the layer to associate the `LinkId` of the channel with the
peer's full Sphinx identity. The Nonce is also used in future tree communications.

Periodically, the node evaluates its position within 3 separate spanning trees, based upon secure hashing of node id's
three different ways. The nodes with lowest hashed id are regarded as network wide roots. The use of several separate
trees is partly to allow some level of protection against malicious control, but also to allow inevitable node churn and
root replacements to not interrupt all routing. As per standard self-stabilizing spanning tree algorithms, each node
starts as a root and then defers to any peers as tree parent if they advertise a lower root and shortest path to that
root. The details are as per Martin Byrenheid algorithm, so that a secure signed path to the root is given as evidence
by each peer. Any node that regards itself as a root must keep updating its hash version, ultimately requiring an id
reset. Also, any node that changes path configuration increments its version to aid flushing out stale information. The
current state information is periodically sent to the peers in a `TreeState` message.

Ultimately, the goal of forming a spanning tree is that each node can define its `NetworkAddressInfo`. This contains a
hashed summary of each node's path to root on all three trees and also the public `VersionedIdentity` of the node.
Using, this information packets can be Greedy routed through the trees from one node to another. During this process
each intermediate node uses ECIES style hybrid encryption to record a secure return path that can be decoded by the
recipient. When the recipient decrypts this path it can cache it and in future use Sphinx protocol packets to send
future message without the uncertainties of greedy routing. In general greedy routing is therefore reserved for node
discovery.

### Peer discovery and Distributed Hash Table

The layer above the spanning tree layer is responsible for allowing peers to lookup full routing addresses from hashed
identifiers, as well as supplying a general Distributed Hash Table (DHT) for global application data and forwarding
services for upper layers. It is expected in future that private groups would lodge an encrypted blob in this DHT that
gives mapping from higher level group keys to transient network keys of all group members (
like [Weidner, M., Kleppmann, M., Hugenroth, D., Beresford, A.R, 2021](https://dl.acm.org/doi/pdf/10.1145/3460120.3484542)).
For now peers must transmit their identifiers out-of-band.

The operation of the Distributed Hash Table is currently carried out using
a [`Chord`](https://en.wikipedia.org/wiki/Chord_(peer-to-peer)) style protocol. I did originally develop
a [`Kademlia`](https://en.wikipedia.org/wiki/Kademlia) approach, but at larger network sizes this seemed to fail some
node lookups suggesting partitioning (Possibly due to issues discussed
in [Yi, W., 2023.](https://scale.iti.kit.edu/_media/resources/theses/ma_wendy_yi.pdf)). The current `Chord` approach
forms three rings (again by hashing node ids in different ways) and periodically gossips peer data to next and previous
nodes in each ring. A finger table isn't used, but the permuted rings allow rapid discovery when searching for `nearer`
nodes that may hold the queried key. The peer list is bounded at each node by evicting nearby node id's when a fresher
insert would overflow the set.

### Reliable Session Layer

The reliable session layer builds on top of the peer discovery layer. It queries for a complete route to peer using the
DHT and greedy routing. Then it coordinates a TCP-like sliding window protocol using Sphinx packets over the discovered
path.

## Building and Running

The project is built as a standard gradle 8.8 project using Kotlin 2.0 and requiring Java 21+ JVM to run. So install a
suitable JVM and gradle and then from the root directory run:

`./gradlew installDist`

The output application wrappers will be generated in `build/install/SecureF2F/` and can be run from the scripts
in `build/install/SecureF2F/bin` so long as a suitable Java install is detected from `JAVA_HOME`:

`./build/install/SecureF2F/bin/SecureF2F --dht --stream`

## Command Line options

Use --help to show the options, which are reproduced below

```
Usage:  [-hV] [-d=<minDegree>] [-g=<networkGenerator>] [-n=<networkSize>]
        [-t=<transportMode>] [--dht [-p=<dhtPasses>]] [--stream
        [-o=<openAttempts>] [-m=<messages>]]
  -n, --size=<networkSize>   Set network initial size
                               Default: 1000
  -t, --transport=<transportMode>
                             Set the peer-to-peer transport substrate.
                             Valid values: Memory, TCP, HTTPS
                               Default: Memory
  -g, --generator=<networkGenerator>
                             Set the graph generation algorithm.
                             Valid values: MinimumDegree, BarabasiAlbert,
                               Linear, ASNetwork
                             MinimumDegree - Nodes are added sequentially with
                               minDegree edges to uniform random previous nodes
                             BarabasiAlbert - Nodes are linked according to the
                               Barabási-Albert scale free model
                             Linear - Nodes are added in a line, mostly for
                               testing code
                             ASNetwork - Nodes are mapped as per the AS
                               internet core on January 02 2000 taken from
                               https://snap.stanford.edu/data/as-733.html
                               Default: MinimumDegree
  -d, --degree=<minDegree>   minimum node degree
                               Default: 3
  -h, --help                 Show this help message and exit.
  -V, --version              Print version information and exit.
DHT experiments
      --dht                  run experiment on DHT storage and retrieval
  -p, --dhtPasses=<dhtPasses>
                             poll DHT until <dhtPasses> consecutive successes
                               Default: 10
Stream Experiments
      --stream               run experiment to setup a stream between nodes and
                               send messages
  -o, --openAttempts=<openAttempts>
                             Allow <openAttempts> attempts to open the stream
                               route
                               Default: 10
  -m, --messageCount=<messages>
                             Send <messageCount> messages down the stream
                               before closing
                               Default: 2000
                               
```

A recommended starting choice is:

`-n 1000 -t TCP --dht --stream`

which will use a local TCP transport for a 1000 nodes and demonstrate DHT capabilities and then sets up a reliable
stream to send 2000 messages between peers. It will take a little while for the network to stabilize. Also, 1000 nodes
is very CPU intensive and there are also limits to how many TCP sockets a PC can host, so higher numbers of nodes may
fail. As such, the `ASNetwork` mode is largely aspirational as it is very resource intensive and tends to time out the
underlying tree heartbeats.

## Module Contents

* `avro` - Contains a framework for serializing and deserializing Kotlin classes using Avro schemas. This follows a more
  manual approach than many frameworks, but this makes it easier to manage the Kotlin classes.
* `crypto` - Contains various cryptographic wrappers and algorithms
    * `main/kotlin/src/uk/co/nesbit/crypto/blockdag/` - Experiments with Byzantine causal block exhange protocols in
      style of [Kleppmann, M., and Heidi H., 2020](https://arxiv.org/pdf/2012.00472)
    * `main/kotlin/src/uk/co/nesbit/crypto/groups/` - Incomplete work on trying to create a CRDT style secure group
      management protocol, built on top of the blockdag code,
    * `main/kotlin/src/uk/co/nesbit/crypto/merkle/` - Geberal support for merkle trees and proof (both audit and log)
    * `main/kotlin/src/uk/co/nesbit/crypto/proxykeystore/` - Custom KeyStore provider allowing a synthetic keystore to
      be passed into libraries, with a callback for signing, which allows integration of HSMs
    * `main/kotlin/src/uk/co/nesbit/crypto/setsync/` - Implementation
      of [Eppstein, D., et al. 2011](https://conferences.sigcomm.org/sigcomm/2011/papers/sigcomm/p218.pdf)
    * `main/kotlin/src/uk/co/nesbit/crypto/ratchet/` - Implementation
      of [signal double ratchet protocol](https://signal.org/docs/specifications/doubleratchet/)
    * `main/kotlin/src/uk/co/nesbit/crypto/session/` - Implementation of Sigma-R authenticated key exchange protocol
      from [Krawczyk, H. 2003](https://www.iacr.org/cryptodb/archive/2003/CRYPTO/1495/1495.pdf)
    * `main/kotlin/src/uk/co/nesbit/crypto/sphinx/` - Implementation of Sphinx MIX protocol
    * `main/kotlin/src/uk/co/nesbit/crypto/BloomFilter.kt` - Bloom filter code
    * `main/kotlin/src/uk/co/nesbit/crypto/CryptoHelpers.kt` - various helpful wrappers over Java cryptographic APIs
    * `main/kotlin/src/uk/co/nesbit/crypto/DigitalSignature.kt` - wrapper over digitial signature APIs and serialization
    * `main/kotlin/src/uk/co/nesbit/crypto/Ecies.kt` - Hybrid crypto code allowing AES-GCM encrypted messages to be sent
      to Diffie-Hellman Public Keys
    * `main/kotlin/src/uk/co/nesbit/crypto/PublicKeyHelper.kt` - wrapper over PublicKey algorithms and serialization
    * `main/kotlin/src/uk/co/nesbit/crypto/SecureHash.kt` - wrapper over secure digest algorithms and serialization
    * `main/kotlin/src/uk/co/nesbit/crypto/X509.kt` - wrapper over BouncyCastle code for making and managing
      Certificates and Certificate Signing Requests.
* `network` - The main code of the Secure Friend-to-Friend system. Built using an Actor model to make the intrinsically
  asynchronous nature of the protocols.
    * `main/kotlin/src/uk/co/nesbit/network/api/` - Configuration, setup and internal API classes
        * `main/kotlin/src/uk/co/nesbit/network/api/net/` - Abstraction for physical message transport layer
        * `main/kotlin/src/uk/co/nesbit/network/api/services/` - Interface for Key management, so that ultimately keys
          could be stored in an HSM
        * `main/kotlin/src/uk/co/nesbit/network/api/tree/` - The message classes encrypted and plain used to transmit at
          the spanning tree and overlay network layers
    * `main/kotlin/src/uk/co/nesbit/network/httpsnet/` - Actor supporting inter-node messaging over `Netty` HTTPS
    * `main/kotlin/src/uk/co/nesbit/network/mocknet/` - Actor supporting inter-node messaging over in memory queues
    * `main/kotlin/src/uk/co/nesbit/network/netty/` - Implementation of `Netty` boiler plate code to provide general TCP
      and HTTPS clients and servers
    * `main/kotlin/src/uk/co/nesbit/network/services/` - Implementation of simple in memory key management service
    * `main/kotlin/src/uk/co/nesbit/network/tcpnet/` - Actor supporting inter-node messaging over TCP links
    * `main/kotlin/src/uk/co/nesbit/network/treeEngine/` - Main actor support of the network protocols
        * `main/kotlin/src/uk/co/nesbit/network/treeEngine/HopRoutingActor.kt    ` - Actor responsible for DHT and Peer
          discovery protocols on top of `NeighbourLinkActor`. Forwards messages to/from session layer
        * `main/kotlin/src/uk/co/nesbit/network/treeEngine/NeighbourLinkActor.kt` - Actor responsible for opening
          configured links via transport layer, organizing the secure spanning tree layer and forwarding Greedy Routed
          and Sphinx packets to/from upper layers.
        * `main/kotlin/src/uk/co/nesbit/network/treeEngine/RootNodeActor.kt` - Actor that represents a node instance and
          automatically creates the various protocol Actors as children in response to config.
        * `main/kotlin/src/uk/co/nesbit/network/treeEngine/SessionActor.kt` - Actor responsible for managing a TCP-like
          reliable messaging layer sitting on top of the `HopRoutingActor` for encrypted message and peer discovery
          services.
* `simpleactor` - My own Kotlin based, 'mostly drop-in', replacement for `AKKA` untyped Actors. I wrote this so I could
  fully remove `AKKA` after they changed their licence terms.
* `src/main/kotlin/uk/co/nesbit/Main.kt` - Main class entry point for running the simulations

## Future Work

Currently, there is plenty more to work on.

1. It has proved very difficult to write good tests for the protocols. Many of their properties are emergent and
   probabilistic with large variability. I have tried to make things separable, but I do need to look at more thorough
   tests. The other modules were much easier to unit test.
2. I want to complete the group membership work so that a founder can form a group. Invite new members. Promote them to
   administrators and evict people. All while maintaining the dynamic mappings between long term identities and the
   relatively short lived network keys.
3. Practical business applications need to coordinate agreements. My own experiences suggest that BlockChains are
   overkill, but Distributed Atomic Commitment protocols
   like [Babaoglu, O., and Toueg, S.. 1993](http://www.disi.unitn.it/~montreso/ds/papers/AtomicCommitment.pdf) are
   likely sufficient and could be built on top of the routing layers.

## References

1. Babaoglu, O., & Toueg, S. (1993). Understanding non-blocking atomic commitment. Distributed systems, 147-168.
1. Beato, F., Halunen, K., & Mennink, B. (2016). Improving the sphinx mix network. In Cryptology and Network Security:
   15th International Conference, CANS 2016, Milan, Italy, November 14-16, 2016, Proceedings 15 (pp. 681-691). Springer
   International Publishing.
1. Byrenheid, M., Roos, S., & Strufe, T. (2019, October). Attack-resistant spanning tree construction in
   route-restricted overlay networks. In 2019 38th Symposium on Reliable Distributed Systems (SRDS) (pp. 251-25109).
   IEEE.
1. Byrenheid, M., Strufe, T., & Roos, S. (2020, September). Secure embedding of rooted spanning trees for scalable
   routing in topology-restricted networks. In 2020 International Symposium on Reliable Distributed Systems (SRDS) (pp.
   175-184). IEEE.
1. Byrenheid, M., Roos, S., & Strufe, T. (2022, January). Topology Inference of Networks utilizing Rooted Spanning Tree
   Embeddings. In Proceedings of the 23rd International Conference on Distributed Computing and Networking (pp.
   107-116).
1. Danezis, G., & Goldberg, I. (2009, May). Sphinx: A compact and provably secure mix format. In 2009 30th IEEE
   Symposium on Security and Privacy (pp. 269-282). IEEE.
1. Eppstein, D., Goodrich, M. T., Uyeda, F., & Varghese, G. (2011). What's the difference? Efficient set reconciliation
   without prior context. ACM SIGCOMM Computer Communication Review, 41(4), 218-229.
1. Kleppmann, M., & Howard, H. (2020). Byzantine eventual consistency and the fundamental limits of peer-to-peer
   databases. arXiv preprint arXiv:2012.00472.
1. Krawczyk, H. (2003, August). SIGMA: The ‘SIGn-and-MAc’approach to authenticated Diffie-Hellman and its use in the IKE
   protocols. In Annual international cryptology conference (pp. 400-425). Berlin, Heidelberg: Springer Berlin
   Heidelberg.
1. Weidner, M., Kleppmann, M., Hugenroth, D., & Beresford, A. R. (2021, November). Key agreement for decentralized
   secure group messaging with strong security guarantees. In Proceedings of the 2021 ACM SIGSAC Conference on Computer
   and Communications Security (pp. 2024-2045).
1. Yi, W. (2023). Towards a Theoretical Analysis of the Routing Architecture KIRA (Doctoral dissertation, Informatics
   Institute).