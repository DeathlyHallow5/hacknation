-- Scope policy (ASI_ALLOWED_PORTS): the core refuses top-N presets, so the built-in profiles
-- above cannot run unless the operator approves their ports. "Laboratorium" scans exactly the
-- approved ports (preset "allowed") — the profile for the local lab and a first scan.
INSERT INTO scan_profiles (name, description, builtin, config) VALUES
('Laboratorium', 'Porty zatwierdzone przez administratora (ASI_ALLOWED_PORTS), 100 zapytań/s — laboratorium i pierwszy skan.', true,
 '{"ports":{"preset":"allowed","custom":""},"rate_limit_rps":100,"max_concurrency":64,"nmap_timing":"T3",
   "host_timeout_s":60,"http_probe":true,"tls_probe":true,"follow_redirects":true,"max_redirects":3,
   "signatures":"all","signature_ids":[],"unstable_retries":1,"batch_strategy":"auto","batch_prefix":24}')
ON CONFLICT DO NOTHING;
