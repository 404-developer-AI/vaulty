-- A Microsoft 365 tenant is connected to at most one organization at a time, but a deleted tenant no longer counts:
-- the same tenant can be connected again after its deletion (the deleted row keeps its history and audit references).
ALTER TABLE vaulty.tenants DROP CONSTRAINT tenants_entra_tenant_id_key;
CREATE UNIQUE INDEX ux_tenants_entra_tenant_connected ON vaulty.tenants (entra_tenant_id) WHERE state <> 'deleted';
