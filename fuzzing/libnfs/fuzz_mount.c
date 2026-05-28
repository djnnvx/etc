/*
 * MOUNT protocol replies (NFSv3 mount path). The MOUNT protocol runs
 * BEFORE any NFS authentication negotiation, so it's the first surface a
 * malicious server can attack. mountres3 contains a variable-length
 * list of supported auth flavours and a file handle, exports replies
 * are linked lists of export entries with embedded group lists.
 *
 * The exports decoder in particular walks attacker-supplied linked-list
 * chains; cycle-checks tend to be lax in legacy XDR codepaths.
 */
#include "harness.h"
#include "libnfs-raw-mount.h"

typedef bool_t (*mount_dec)(ZDR *, void *);

#define DEC(name)  { #name, (mount_dec)zdr_##name, sizeof(name) }

static const struct {
    const char *name;
    mount_dec fn;
    size_t result_size;
} decoders[] = {
    DEC(mountres3),
    DEC(exports),
    DEC(mountlist),
    DEC(mountres1),
    DEC(MOUNT1MNTres),
    DEC(MOUNT1DUMPres),
};
#define N_DEC (sizeof(decoders) / sizeof(decoders[0]))

static int fuzz_one(const uint8_t *data, size_t size)
{
    if (size < 1)
        return 0;
    unsigned idx = data[0] % N_DEC;
    const uint8_t *payload = data + 1;
    size_t payload_size = size - 1;

    ZDR zdr;
    nfs_zdrmem_decode(&zdr, payload, payload_size);

    void *res = calloc(1, decoders[idx].result_size);
    if (!res) {
        zdr_destroy(&zdr);
        return 0;
    }
    if (decoders[idx].fn(&zdr, res)) {
        zdr_free((zdrproc_t)decoders[idx].fn, (caddr_t)res);
    }
    free(res);
    zdr_destroy(&zdr);
    return 0;
}
