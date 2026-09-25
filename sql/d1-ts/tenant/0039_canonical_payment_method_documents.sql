-- Single authority: the admin document; typed SQL readers use an indexed view.
-- Merge the former runtime authority into existing documents before dropping it.
INSERT INTO tenant_resources (resource_kind,resource_id,document_json,revision,created_at_unix,updated_at_unix)
SELECT 'payment-methods',id,json_object('id', id, 'tenant_id', tenant_id, 'provider', provider, 'provider_customer_id', provider_customer_id, 'provider_payment_method_id', provider_payment_method_id, 'is_default', json(CASE WHEN COALESCE(is_default,0)=1 THEN 'true' ELSE 'false' END), 'created_at', created_at_unix),1,created_at_unix,created_at_unix FROM payment_methods WHERE true
ON CONFLICT (resource_kind,resource_id) DO UPDATE SET
 document_json=json_patch(tenant_resources.document_json,excluded.document_json);
DROP TABLE payment_methods;
CREATE VIEW payment_methods AS SELECT
resource_id AS id,
COALESCE(json_extract(document_json,'$.tenant_id'),'') AS tenant_id,
COALESCE(json_extract(document_json,'$.provider'),'') AS provider,
COALESCE(json_extract(document_json,'$.provider_customer_id'),'') AS provider_customer_id,
COALESCE(json_extract(document_json,'$.provider_payment_method_id'),'') AS provider_payment_method_id,
CASE WHEN json_type(document_json,'$.is_default')='true' THEN 1 WHEN json_type(document_json,'$.is_default')='false' THEN 0 ELSE 0 END AS is_default,
CASE WHEN json_type(document_json,'$.created_at') IN ('integer','real') THEN json_extract(document_json,'$.created_at') ELSE created_at_unix END AS created_at_unix
FROM tenant_resources WHERE resource_kind='payment-methods' AND length(trim(COALESCE(json_extract(document_json,'$.provider'),'')))>0 AND length(trim(COALESCE(json_extract(document_json,'$.provider_payment_method_id'),'')))>0;
CREATE TRIGGER payment_methods_document_insert INSTEAD OF INSERT ON payment_methods
BEGIN
 INSERT INTO tenant_resources(resource_kind,resource_id,document_json,revision,created_at_unix,updated_at_unix)
 VALUES('payment-methods',NEW.id,json_object('id', NEW.id, 'tenant_id', NEW.tenant_id, 'provider', NEW.provider, 'provider_customer_id', NEW.provider_customer_id, 'provider_payment_method_id', NEW.provider_payment_method_id, 'is_default', json(CASE WHEN COALESCE(NEW.is_default,0)=1 THEN 'true' ELSE 'false' END), 'created_at', NEW.created_at_unix),1,COALESCE(NEW.created_at_unix,unixepoch()),COALESCE(NEW.created_at_unix,unixepoch()));
END;
CREATE TRIGGER payment_methods_document_update INSTEAD OF UPDATE ON payment_methods
BEGIN
 UPDATE tenant_resources SET document_json=json_patch(document_json,json_object('id', NEW.id, 'tenant_id', NEW.tenant_id, 'provider', NEW.provider, 'provider_customer_id', NEW.provider_customer_id, 'provider_payment_method_id', NEW.provider_payment_method_id, 'is_default', json(CASE WHEN COALESCE(NEW.is_default,0)=1 THEN 'true' ELSE 'false' END), 'created_at', NEW.created_at_unix)),revision=revision+1,updated_at_unix=COALESCE(NEW.created_at_unix,unixepoch()) WHERE resource_kind='payment-methods' AND resource_id=OLD.id;
END;
CREATE TRIGGER payment_methods_document_delete INSTEAD OF DELETE ON payment_methods
BEGIN
 DELETE FROM tenant_resources WHERE resource_kind='payment-methods' AND resource_id=OLD.id;
END;
CREATE UNIQUE INDEX idx_payment_methods_document_provider ON tenant_resources(COALESCE(json_extract(document_json,'$.tenant_id'),''),COALESCE(json_extract(document_json,'$.provider'),''),COALESCE(json_extract(document_json,'$.provider_payment_method_id'),'')) WHERE resource_kind='payment-methods' AND length(trim(COALESCE(json_extract(document_json,'$.provider'),'')))>0 AND length(trim(COALESCE(json_extract(document_json,'$.provider_payment_method_id'),'')))>0;
