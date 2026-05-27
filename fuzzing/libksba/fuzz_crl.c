/*
 * CRL parsing: dirmngr fetches CRLs over HTTP/LDAP and parses them here, so this
 * is a remote attacker-controlled path (and CVE-2022-3515's home). Iterated
 * ksba_crl_parse pulls each revoked entry, then the accessors drive the rest.
 */
#include "harness.h"

static int fuzz_one(const uint8_t *data, size_t size)
{
    ksba_reader_t reader;
    ksba_crl_t crl;
    ksba_stop_reason_t sr = KSBA_SR_RUNNING;
    int guard = 0;

    if (ksba_reader_new(&reader))
        return 0;
    if (ksba_reader_set_mem(reader, data, size)) {
        ksba_reader_release(reader);
        return 0;
    }
    if (ksba_crl_new(&crl)) {
        ksba_reader_release(reader);
        return 0;
    }
    ksba_crl_set_reader(crl, reader);

    do {
        if (ksba_crl_parse(crl, &sr))
            break;
        if (sr == KSBA_SR_GOT_ITEM) {
            ksba_sexp_t serial = NULL;
            ksba_isotime_t rdate;
            ksba_crl_reason_t reason;
            if (!ksba_crl_get_item(crl, &serial, rdate, &reason))
                ksba_free(serial);
        }
    } while (sr != KSBA_SR_READY && ++guard < 100000);

    {
        char *issuer = NULL;
        ksba_isotime_t this_update, next_update;
        ksba_sexp_t number = NULL, kid = NULL, ser = NULL;
        ksba_name_t nm = NULL;
        int i;

        if (!ksba_crl_get_issuer(crl, &issuer))
            ksba_free(issuer);
        (void)ksba_crl_get_digest_algo(crl);             /* const, do not free */
        ksba_crl_get_update_times(crl, this_update, next_update);
        ksba_free(ksba_crl_get_sig_val(crl));
        if (!ksba_crl_get_crl_number(crl, &number))
            ksba_free(number);
        if (!ksba_crl_get_auth_key_id(crl, &kid, &nm, &ser)) {
            ksba_free(kid);
            ksba_free(ser);
            drain_name(nm);
        }
        for (i = 0; i < KSBA_FUZZ_MAXITER; i++) {
            const char *oid;
            const unsigned char *der;
            size_t derlen;
            int crit;
            if (ksba_crl_get_extension(crl, i, &oid, &crit, &der, &derlen))
                break;
        }
    }

    ksba_crl_release(crl);
    ksba_reader_release(reader);
    return 0;
}
