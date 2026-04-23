-- Reverse of 000057 up: zalo_oa → zalo_oauth; zalo_bot → zalo_oa.
-- Uses the same sentinel-swap pattern.

UPDATE channel_instances SET channel_type = 'zalo_oa_tmp' WHERE channel_type = 'zalo_oa';
UPDATE channel_instances SET channel_type = 'zalo_oa'     WHERE channel_type = 'zalo_bot';
UPDATE channel_instances SET channel_type = 'zalo_oauth'  WHERE channel_type = 'zalo_oa_tmp';
