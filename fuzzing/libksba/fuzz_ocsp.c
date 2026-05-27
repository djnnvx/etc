/*
 * OCSP response parsing: dirmngr fetches these over HTTP, so it is a remote
 * attacker-controlled path. ksba_ocsp_parse_response takes a raw buffer and
 * parses eagerly (ocsp.c + time.c); the accessors drain the remainder.
 */
#include "harness.h"

static int fuzz_one(const uint8_t *data, size_t size)
{
    ksba_ocsp_t ocsp;
    ksba_ocsp_response_status_t rstatus;

    if (ksba_ocsp_new(&ocsp))
        return 0;

    if (!ksba_ocsp_parse_response(ocsp, data, size, &rstatus)) {
        char *name = NULL;
        ksba_sexp_t kid = NULL;
        ksba_isotime_t produced_at;
        int i;

        if (!ksba_ocsp_get_responder_id(ocsp, &name, &kid)) {
            ksba_free(name);
            ksba_free(kid);
        }
        ksba_free(ksba_ocsp_get_sig_val(ocsp, produced_at));
        (void)ksba_ocsp_get_digest_algo(ocsp);           /* const, do not free */

        for (i = 0; i < KSBA_FUZZ_MAXITER; i++) {
            ksba_cert_t c = ksba_ocsp_get_cert(ocsp, i);
            if (!c)
                break;
            ksba_cert_release(c);
        }
    }

    ksba_ocsp_release(ocsp);
    return 0;
}
