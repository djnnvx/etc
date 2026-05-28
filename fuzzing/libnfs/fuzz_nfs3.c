/*
 * NFSv3 reply parsing. Attacker model: malicious NFS server. Victim's libnfs
 * client (e.g. VLC's nfs:// handler, kodi, gvfs) sends a request; we replay
 * the response payload directly through the per-procedure ZDR decoder.
 *
 * Cycle through the major NFS3 result types so a single corpus exercises
 * GETATTR/READ/READDIR/LOOKUP/FSINFO/...; the first byte of the fuzz input
 * selects which decoder runs (mod the number of decoders).
 */
#include "harness.h"
#include "libnfs-raw-nfs.h"

typedef bool_t (*nfs3_dec)(ZDR *, void *);

#define DEC(name)  { #name, (nfs3_dec)zdr_##name, sizeof(name) }

static const struct {
    const char *name;
    nfs3_dec fn;
    size_t result_size;
} decoders[] = {
    DEC(GETATTR3res),
    DEC(SETATTR3res),
    DEC(LOOKUP3res),
    DEC(ACCESS3res),
    DEC(READLINK3res),
    DEC(READ3res),
    DEC(WRITE3res),
    DEC(CREATE3res),
    DEC(MKDIR3res),
    DEC(SYMLINK3res),
    DEC(MKNOD3res),
    DEC(REMOVE3res),
    DEC(RMDIR3res),
    DEC(RENAME3res),
    DEC(LINK3res),
    DEC(READDIR3res),
    DEC(READDIRPLUS3res),
    DEC(FSSTAT3res),
    DEC(FSINFO3res),
    DEC(PATHCONF3res),
    DEC(COMMIT3res),
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

    /* Calloc'd target struct so any uninitialised pointer fields are NULL;
     * the decoder will overwrite the parts it parses. Leaks ignored. */
    void *res = calloc(1, decoders[idx].result_size);
    if (!res) {
        zdr_destroy(&zdr);
        return 0;
    }

    if (decoders[idx].fn(&zdr, res)) {
        /* Decode succeeded - the post-decode free walks the same struct
         * shape and exercises any boundary cases in zdr_free. */
        zdr_free((zdrproc_t)decoders[idx].fn, (caddr_t)res);
    }
    free(res);
    zdr_destroy(&zdr);
    return 0;
}
