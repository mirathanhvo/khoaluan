#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <relic.h>
#include "private.h"
#include "bswabe.h"
#include "common.h"

/**
 * Function to delegate a secret key to a new user with a reduced attribute set.
 */
void delegate_key(bswabe_prv_t* sk, bswabe_prv_t* new_sk, char** new_attrs, int new_attr_count) {
    int i;

    // Allocate memory for new secret key components
    new_sk->comps = malloc(new_attr_count * sizeof(bswabe_prv_comp_t));
    if (!new_sk->comps) {
        printf("Memory allocation error for new attribute components.\n");
        exit(1);
    }
    new_sk->comps_len = new_attr_count;

    // Copy the d component (PBC → RELIC)
    g2_null(new_sk->d);
    g2_new(new_sk->d);
    g2_copy(new_sk->d, sk->d);

    // Iterate through attributes and copy matching ones
    for (i = 0; i < new_attr_count; i++) {
        int found = 0;
        for (int j = 0; j < sk->comps_len; j++) {
            bswabe_prv_comp_t* comp = &sk->comps[j];
            if (strcmp(comp->attr, new_attrs[i]) == 0) {
                found = 1;
                bswabe_prv_comp_t new_comp;
                new_comp.attr = strdup(new_attrs[i]);

                g1_null(new_comp.d);
                g1_new(new_comp.d);
                g1_copy(new_comp.d, comp->d);

                g1_null(new_comp.dp);
                g1_new(new_comp.dp);
                g1_copy(new_comp.dp, comp->dp);

                new_sk->comps[i] = new_comp;
                break;
            }
        }
        if (!found) {
            printf("Error: Attribute %s not found in the original key!\n", new_attrs[i]);
            exit(1);
        }
    }
}

/**
 * Main function to handle the delegation process.
 * Usage: ./delegate <input_key> <output_key> <attr1> [attr2 ...]
 */
int main(int argc, char** argv) {
    if (argc < 4) {
        printf("Usage: %s <input_key> <output_key> <attr1> [attr2 ...]\n", argv[0]);
        return 1;
    }

    // Initialize RELIC
    if (core_init() != RLC_OK) {
        printf("Error initializing RELIC.\n");
        return 1;
    }

    if (pc_param_set_any() != RLC_OK) {
        printf("Error: Failed to set up pairing parameters.\n");
        core_clean();
        return 1;
    }

    // Open and read input secret key file
    FILE* input_fp = fopen(argv[1], "rb");
    if (!input_fp) {
        printf("Error opening input key file: %s\n", argv[1]);
        core_clean();
        return 1;
    }
    
    // Determine file size
    fseek(input_fp, 0, SEEK_END);
    size_t file_size = ftell(input_fp);
    rewind(input_fp);

    // Read file into buffer
    uint8_t* input_buf = malloc(file_size);
    if (!input_buf) {
        printf("Memory allocation error for input buffer.\n");
        fclose(input_fp);
        core_clean();
        return 1;
    }
    fread(input_buf, 1, file_size, input_fp);
    fclose(input_fp);

    // Deserialize secret key
    bswabe_prv_t* sk = bswabe_prv_unserialize(input_buf, file_size);
    free(input_buf);
    
    if (!sk) {
        printf("Error: Failed to deserialize the input secret key.\n");
        core_clean();
        return 1;
    }

    // Allocate memory for new delegated key
    bswabe_prv_t* new_sk = malloc(sizeof(bswabe_prv_t));
    if (!new_sk) {
        printf("Memory allocation error for new secret key.\n");
        bswabe_prv_free(sk);
        core_clean();
        return 1;
    }

    // Delegate the key with new attributes
    delegate_key(sk, new_sk, &argv[3], argc - 3);

    // Serialize and save the new delegated key
    size_t output_size;
    uint8_t* output_buf = bswabe_prv_serialize(new_sk, &output_size);
    if (!output_buf) {
        printf("Error: Failed to serialize the new secret key.\n");
        bswabe_prv_free(sk);
        bswabe_prv_free(new_sk);
        core_clean();
        return 1;
    }

    FILE* output_fp = fopen(argv[2], "wb");
    if (!output_fp) {
        printf("Error opening output key file: %s\n", argv[2]);
        bswabe_prv_free(sk);
        bswabe_prv_free(new_sk);
        free(output_buf);
        core_clean();
        return 1;
    }

    if (fwrite(output_buf, 1, output_size, output_fp) != output_size) {
        printf("Error: Failed to write the output key file.\n");
        bswabe_prv_free(sk);
        bswabe_prv_free(new_sk);
        free(output_buf);
        fclose(output_fp);
        core_clean();
        return 1;
    }
    fclose(output_fp);
    free(output_buf);

    printf("Delegated key saved to %s\n", argv[2]);

    // Cleanup
    bswabe_prv_free(sk);
    bswabe_prv_free(new_sk);
    core_clean();

    return 0;
}
