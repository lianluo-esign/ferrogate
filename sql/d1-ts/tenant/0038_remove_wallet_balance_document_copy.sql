-- A wallet without a physical balance row has not adopted prepaid billing yet:
-- its opening balance is still authoritative and must not be removed.
UPDATE tenant_resources SET document_json=json_remove(document_json,'$.balance_cents','$.balance_credits')
WHERE resource_kind='wallets' AND EXISTS(SELECT 1 FROM wallets WHERE wallets.tenant_id=tenant_resources.resource_id);
