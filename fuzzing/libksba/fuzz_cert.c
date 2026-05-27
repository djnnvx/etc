/*
 * X.509 cert parsing via ksba_cert_init_from_mem. Parsing is lazy, so the
 * accessors below force the deep parse (cert/dn/keyinfo/name/oid/time).
 * Reachable via gpgsm with an attacker-supplied certificate.
 */
#include "harness.h"

static int fuzz_one(const uint8_t *data, size_t size)
{
    ksba_cert_t cert;

    if (ksba_cert_new(&cert))
        return 0;

    if (!ksba_cert_init_from_mem(cert, data, size)) {
        char *s;
        ksba_isotime_t t;
        ksba_sexp_t kid, serial;
        ksba_name_t nm, nm2;
        ksba_crl_reason_t reason;
        const char *oid;
        int i, crit, ca, pathlen;
        unsigned int flags;
        size_t off, len;

        ksba_free(ksba_cert_get_serial(cert));
        (void)ksba_cert_get_digest_algo(cert);          /* const, do not free */

        for (i = 0; i < KSBA_FUZZ_MAXITER && (s = ksba_cert_get_issuer(cert, i)); i++)
            ksba_free(s);
        for (i = 0; i < KSBA_FUZZ_MAXITER && (s = ksba_cert_get_subject(cert, i)); i++)
            ksba_free(s);

        ksba_cert_get_validity(cert, 0, t);
        ksba_cert_get_validity(cert, 1, t);

        ksba_free(ksba_cert_get_public_key(cert));
        ksba_free(ksba_cert_get_sig_val(cert));

        for (i = 0; i < KSBA_FUZZ_MAXITER &&
             !ksba_cert_get_extension(cert, i, &oid, &crit, &off, &len); i++)
            ;

        ksba_cert_is_ca(cert, &ca, &pathlen);
        ksba_cert_get_key_usage(cert, &flags);
        if (!ksba_cert_get_cert_policies(cert, &s))
            ksba_free(s);
        if (!ksba_cert_get_ext_key_usages(cert, &s))
            ksba_free(s);

        for (i = 0; i < KSBA_FUZZ_MAXITER; i++) {
            nm = nm2 = NULL;
            if (ksba_cert_get_crl_dist_point(cert, i, &nm, &nm2, &reason))
                break;
            drain_name(nm);
            drain_name(nm2);
        }

        kid = serial = NULL;
        nm = NULL;
        if (!ksba_cert_get_auth_key_id(cert, &kid, &nm, &serial)) {
            ksba_free(kid);
            ksba_free(serial);
            drain_name(nm);
        }
        kid = NULL;
        if (!ksba_cert_get_subj_key_id(cert, &crit, &kid))
            ksba_free(kid);

        for (i = 0; i < KSBA_FUZZ_MAXITER; i++) {
            char *method = NULL;
            nm = NULL;
            if (ksba_cert_get_authority_info_access(cert, i, &method, &nm))
                break;
            ksba_free(method);
            drain_name(nm);
        }
        for (i = 0; i < KSBA_FUZZ_MAXITER; i++) {
            char *method = NULL;
            nm = NULL;
            if (ksba_cert_get_subject_info_access(cert, i, &method, &nm))
                break;
            ksba_free(method);
            drain_name(nm);
        }
    }

    ksba_cert_release(cert);
    return 0;
}
