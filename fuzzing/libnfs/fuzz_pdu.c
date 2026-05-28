/*
 * RPC framing layer. Sits above the per-procedure zdr decoders, below the
 * raw socket read. libnfs_zdr_replymsg parses the rpc_msg envelope (xid,
 * direction, accepted-vs-rejected reply, auth verifier flavour, status).
 *
 * Reachable on every reply from a malicious server, before any
 * NFS-procedure-specific code runs. Bugs here break confinement universally.
 * libnfs_zdr_callmsg sits on the server-side parse path; rarer but exists
 * (servers/rpcbind, etc.).
 *
 * The harness lets the first byte pick the direction (CALL vs REPLY) so a
 * single corpus hits both framings.
 */
#include "harness.h"
/* libnfs.h has to come first - it defines the EXTERN export macro that
 * libnfs-raw.h depends on but does not itself provide. */
#include "nfsc/libnfs.h"
#include "nfsc/libnfs-raw.h"

static int fuzz_one(const uint8_t *data, size_t size)
{
    if (size < 1)
        return 0;
    int as_call = (data[0] & 1);
    const uint8_t *payload = data + 1;
    size_t payload_size = size - 1;

    ZDR zdr;
    struct rpc_msg msg;
    nfs_zdrmem_decode(&zdr, payload, payload_size);
    memset(&msg, 0, sizeof(msg));

    /* libnfs_accepted_reply (zdr.c:534) dispatches on status=SUCCESS by
     * calling msg->body.rbody.reply.areply.reply_data.results.proc which is
     * normally set by rpc_allocate_pdu when sending the request. In a stateless
     * fuzzer we have no pending PDU; plug in the no-op decoder so the SUCCESS
     * branch parses without dereferencing a NULL fn ptr. */
    msg.body.rbody.reply.areply.reply_data.results.proc =
        (zdrproc_t)libnfs_zdr_void;
    msg.body.rbody.reply.areply.reply_data.results.where = NULL;

    struct rpc_context *rpc = rpc_init_context();
    if (!rpc) {
        zdr_destroy(&zdr);
        return 0;
    }

    if (as_call) {
        if (libnfs_zdr_callmsg(rpc, &zdr, &msg)) {
            /* nothing to free - the call body's auth fields aren't owned. */
        }
    } else {
        if (libnfs_zdr_replymsg(rpc, &zdr, &msg)) {
            /* same: reply envelope doesn't own its sub-buffers in this layer. */
        }
    }

    zdr_destroy(&zdr);
    rpc_destroy_context(rpc);
    return 0;
}
