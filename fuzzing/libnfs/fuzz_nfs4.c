/*
 * NFSv4 COMPOUND reply parsing. Largest and most stateful decoder in libnfs:
 * a single COMPOUND4res contains a variable-length array of operation
 * results, each tagged with an opcode that selects a different sub-decoder
 * (nfs_resop4 = tagged union). Prime target for length-confusion and tag
 * mismatch bugs.
 *
 * Reachable client-side via any NFSv4 mount; reachable through VLC/Kodi when
 * the user is tricked into opening an nfs:// URL pointing at attacker's
 * server.
 */
#include "harness.h"
#include "libnfs-raw-nfs4.h"

static int fuzz_one(const uint8_t *data, size_t size)
{
    ZDR zdr;
    COMPOUND4res res;

    nfs_zdrmem_decode(&zdr, data, size);
    memset(&res, 0, sizeof(res));

    if (zdr_COMPOUND4res(&zdr, &res)) {
        zdr_free((zdrproc_t)zdr_COMPOUND4res, (caddr_t)&res);
    }
    zdr_destroy(&zdr);
    return 0;
}
