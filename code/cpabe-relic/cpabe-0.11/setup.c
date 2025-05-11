#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <glib.h>
#include <relic/relic.h>
#include "bswabe.h"
#include "common.h"


char* usage =
"Usage: cpabe-setup [OPTION ...]\n"
"\n"
"Generate system parameters, a public key, and a master secret key\n"
"for use with cpabe-keygen, cpabe-enc, and cpabe-dec.\n"
"\n"
"Output will be written to the files \"pub_key\" and \"master_key\"\n"
"unless the --output-public-key or --output-master-key options are\n"
"used.\n"
"\n"
" -h, --help                    print this message\n"
" -v, --version                 print version information\n"
" -p, --output-public-key FILE  write public key to FILE\n"
" -m, --output-master-key FILE  write master secret key to FILE\n\n";

void parse_args(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            printf("%s", usage); exit(0);
        } else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
            printf(CPABE_VERSION, "-setup"); exit(0);
        } else if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--output-public-key")) {
            if (++i >= argc) die(usage);
            pub_file = argv[i];
        } else if (!strcmp(argv[i], "-m") || !strcmp(argv[i], "--output-master-key")) {
            if (++i >= argc) die(usage);
            msk_file = argv[i];
        } else {
            die(usage);
        }
    }
}

int main(int argc, char** argv) {
    parse_args(argc, argv);
    if (!pub_file)
    pub_file = g_strdup("pub_key");

    if (!msk_file)
    msk_file = g_strdup("master_key");

    if (core_init() != RLC_OK || pc_param_set_any() != RLC_OK)
        die("RELIC initialization failed");

    bswabe_pub_t* pub;
    bswabe_msk_t* msk;
    bswabe_setup(&pub, &msk);

    GByteArray* pub_buf = bswabe_pub_serialize(pub);
    spit_file(pub_file, pub_buf->data, pub_buf->len, 1);

    GByteArray* msk_buf = bswabe_msk_serialize(msk);
    spit_file(msk_file, msk_buf->data, msk_buf->len, 1);

    bswabe_pub_free(pub);
    bswabe_msk_free(msk);
    core_clean();
    return 0;
}
