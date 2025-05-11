#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <relic/relic.h>
#include <time.h>
#include "bswabe.h"
#include "common.h"
#include "policy_lang.h"

char* usage =
"Usage: cpabe-keygen [OPTION ...] PUB_KEY MASTER_KEY ATTR [ATTR ...]\n"
"\n"
"Generate a key with the listed attributes using public key PUB_KEY and\n"
"master secret key MASTER_KEY. Output will be written to the file\n"
"\"priv_key\" unless the -o option is specified.\n"
"\n"
" -h, --help               print this message\n"
" -v, --version            print version information\n"
" -o, --output FILE        write resulting key to FILE\n"
" -d, --deterministic      use deterministic seed for key generation\n\n";

gint
comp_string(gconstpointer a, gconstpointer b) {
    return strcmp((const char*)a, (const char*)b);
}

void parse_args(int argc, char** argv) {
    int i;
    GSList* alist = NULL;
    GSList* ap;
    int n;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            printf("%s", usage);
            exit(0);
        } else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
            printf(CPABE_VERSION, "-keygen");
            exit(0);
        } else if (!strcmp(argv[i], "-o") || !strcmp(argv[i], "--output")) {
            if (++i >= argc)
                die(usage);
            else
                out_file = argv[i];
        } else if (!pub_file) {
            pub_file = argv[i];
        } else if (!msk_file) {
            msk_file = argv[i];
        } else {
            // Parse each input attribute
            parse_attribute(&alist, argv[i]);
        }
    }

    if (!pub_file || !msk_file || !alist)
        die(usage);

    alist = g_slist_sort(alist, comp_string);
    n = g_slist_length(alist);

    attrs = malloc((n + 1) * sizeof(char*));
    i = 0;
    for (ap = alist; ap; ap = ap->next)
        attrs[i++] = ap->data;
    attrs[i] = 0;
}

int main(int argc, char** argv) {
    parse_args(argc, argv);
    if (!out_file) out_file = "priv_key";

    if (core_init() != RLC_OK || pc_param_set_any() != RLC_OK)
        die("RELIC initialization failed");

    bswabe_pub_t* pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
    bswabe_msk_t* msk = bswabe_msk_unserialize(pub, suck_file(msk_file), 1);

    bswabe_prv_t* prv = bswabe_keygen(pub, msk, attrs);
    GByteArray* prv_buf = bswabe_prv_serialize(prv);
    spit_file(out_file, prv_buf->data, prv_buf->len, 1);

    bswabe_pub_free(pub);
    bswabe_msk_free(msk);
    bswabe_prv_free(prv);
    core_clean();
    return 0;
}
