/*
 * CMS / PKCS#7 (S/MIME) parsing, reachable via gpgsm on an attacker-supplied
 * message. Iterated ksba_cms_parse drives the state machine, then the accessors.
 * Largest parser in the tree: cms.c + cms-parser.c.
 */
#include "harness.h"

static int fuzz_one(const uint8_t *data, size_t size)
{
    ksba_reader_t reader;
    ksba_cms_t cms;
    ksba_stop_reason_t sr = KSBA_SR_RUNNING;
    int guard = 0, i;

    if (ksba_reader_new(&reader))
        return 0;
    if (ksba_reader_set_mem(reader, data, size)) {
        ksba_reader_release(reader);
        return 0;
    }
    if (ksba_cms_new(&cms)) {
        ksba_reader_release(reader);
        return 0;
    }
    ksba_cms_set_reader_writer(cms, reader, NULL);

    do {
        if (ksba_cms_parse(cms, &sr))
            break;
    } while (sr != KSBA_SR_READY && ++guard < 100000);

    ksba_cms_get_content_type(cms, 0);
    ksba_cms_get_content_type(cms, 1);

    for (i = 0; i < KSBA_FUZZ_MAXITER && ksba_cms_get_digest_algo_list(cms, i); i++)
        ;
    for (i = 0; i < KSBA_FUZZ_MAXITER; i++) {
        char *issuer = NULL;
        ksba_sexp_t serial = NULL;
        if (ksba_cms_get_issuer_serial(cms, i, &issuer, &serial))
            break;
        ksba_free(issuer);
        ksba_free(serial);
    }
    for (i = 0; i < KSBA_FUZZ_MAXITER; i++) {
        ksba_cert_t c = ksba_cms_get_cert(cms, i);
        if (!c)
            break;
        ksba_cert_release(c);
    }
    for (i = 0; i < KSBA_FUZZ_MAXITER; i++) {
        char *digest = NULL;
        size_t dlen;
        if (ksba_cms_get_message_digest(cms, i, &digest, &dlen))
            break;
        ksba_free(digest);
    }
    for (i = 0; i < KSBA_FUZZ_MAXITER; i++) {
        ksba_isotime_t st;
        if (ksba_cms_get_signing_time(cms, i, st))
            break;
    }
    for (i = 0; i < KSBA_FUZZ_MAXITER; i++) {
        ksba_sexp_t v = ksba_cms_get_sig_val(cms, i);
        if (!v)
            break;
        ksba_free(v);
    }
    for (i = 0; i < KSBA_FUZZ_MAXITER; i++) {
        ksba_sexp_t v = ksba_cms_get_enc_val(cms, i);
        if (!v)
            break;
        ksba_free(v);
    }

    ksba_cms_release(cms);
    ksba_reader_release(reader);
    return 0;
}
