static void spgwu_exit(void);
static void parser(char* buf, int *type_ptr, struct in_addr *ue_ptr, struct in_addr *enb_ptr, uint32_t *i_tei_ptr, uint32_t *o_tei_ptr, uint8_t *bearer_id_ptr);
static void *spgwu_gtp_api_server (void *args_p);
int spgwu_init (void);