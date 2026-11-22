-- A built-in profile for 10 000+ addresses: the approved ports (ASI_ALLOWED_PORTS) at the
-- global maximum rate, so a /18 takes minutes, not the hour "Laboratorium" (100/s) would.
-- Measured: /18 with 160 live hosts, 8 ports at 1000/s — 476 s (docs/BENCHMARK.md).
INSERT INTO scan_profiles (name, description, builtin, config) VALUES
('Duża sieć', 'Porty zatwierdzone przez administratora (ASI_ALLOWED_PORTS), 1000 zapytań/s — sieci od 10 000 adresów.', true,
 '{"ports":{"preset":"allowed","custom":""},"rate_limit_rps":1000,"max_concurrency":100,"nmap_timing":"T3",
   "host_timeout_s":90,"http_probe":true,"tls_probe":true,"follow_redirects":true,"max_redirects":3,
   "signatures":"all","signature_ids":[],"unstable_retries":1,"batch_strategy":"fixed","batch_prefix":22}')
ON CONFLICT DO NOTHING;
