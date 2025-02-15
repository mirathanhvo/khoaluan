bswabe_cph_t*
bswabe_enc(bswabe_pub_t* pub, gt_t m, char* policy)
{
    bswabe_cph_t* cph;
    bn_t s, order;

    /* initialize */
    cph = malloc(sizeof(bswabe_cph_t));

    bn_new(s);
    bn_new(order);
    gt_new(cph->cs);
    g1_new(cph->c);
    cph->p = parse_policy_postfix(policy);

    /* compute */
    gt_rand(m);
    g1_get_ord(order);  // Get the order of the group (typically for G1).
    bn_rand_mod(s, order);
    pc_map(cph->cs, pub->g_hat_alpha, s);
    gt_mul(cph->cs, cph->cs, m);

    g1_mul(cph->c, pub->h, s);

    fill_policy(cph->p, pub, s);

    bn_free(order);
    bn_free(s);

    return cph;
}