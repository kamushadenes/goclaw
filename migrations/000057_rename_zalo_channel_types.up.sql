-- Rename Zalo channel types in channel_instances to align with Zalo's
-- own product taxonomy. Pre-refactor names inverted reality:
--   'zalo_oa'     → static-token Bot variant (actually "zalo_bot")
--   'zalo_oauth'  → phone-tied Official Account via OAuth (the canonical "zalo_oa")
--
-- Three-step swap via zalo_oa_tmp sentinel avoids transient collision even
-- though channel_type has no unique constraint today.

UPDATE channel_instances SET channel_type = 'zalo_oa_tmp' WHERE channel_type = 'zalo_oauth';
UPDATE channel_instances SET channel_type = 'zalo_bot'    WHERE channel_type = 'zalo_oa';
UPDATE channel_instances SET channel_type = 'zalo_oa'     WHERE channel_type = 'zalo_oa_tmp';
