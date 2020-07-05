struct kafs_lookup_context;

extern void *kafs_generate_text_payload(void *result,
					const char *cell_name,
					unsigned int *_ttl,
					struct kafs_lookup_context *ctx);

extern void *kafs_generate_v1_payload(void *result,
				      const char *cell_name,
				      unsigned int *_ttl,
				      struct kafs_lookup_context *ctx);
