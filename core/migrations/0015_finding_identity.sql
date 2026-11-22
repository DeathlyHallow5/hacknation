-- One finding per problem, not one per scan. A finding's identity is its category and entity
-- key (the URL, ip:port/proto, or signature + ip:port/proto), whichever scan observed it; its
-- id is UUIDv5(NAMESPACE_URL, 'asi:finding:<category>:<key>') — `v1::finding_id`. Until now
-- the id also contained the scan, so every one-off scan of the same address produced a copy
-- of the same finding (and an automatic DefectDojo export of each copy).

-- The analyst state belongs to the problem: deleting one of the scans that saw it must not
-- delete it. scan_id now only records the scan of the latest edit.
ALTER TABLE finding_states
    DROP CONSTRAINT finding_states_scan_id_fkey,
    ALTER COLUMN scan_id DROP NOT NULL,
    ADD CONSTRAINT finding_states_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL;

-- Merge the per-scan copies under the new id. Analyst fields come from the most recent copy
-- an analyst actually edited (else the most recent one); the DefectDojo mark from the most
-- recent copy that has one, so an exported problem is not exported again.
CREATE TEMP TABLE finding_states_merged ON COMMIT DROP AS
WITH keyed AS (
    SELECT fs.*,
           encode(set_byte(set_byte(substring(d.h FROM 1 FOR 16), 6, (get_byte(d.h, 6) & 15) | 80),
                           8, (get_byte(d.h, 8) & 63) | 128), 'hex')::uuid AS new_id,
           (fs.status <> 'open' OR fs.score_override IS NOT NULL OR fs.assignee IS NOT NULL
            OR cardinality(fs.tags) > 0 OR fs.notes_enc IS NOT NULL) AS edited
    FROM finding_states fs,
         LATERAL (SELECT digest(decode('6ba7b8119dad11d180b400c04fd430c8', 'hex')
                                || convert_to('asi:finding:' || fs.category || ':' || fs.entity_key, 'UTF8'), 'sha1') AS h) d
)
SELECT DISTINCT ON (k.new_id)
       k.new_id AS finding_id, k.scan_id, k.category, k.entity_key, k.status, k.score_override, k.assignee, k.tags,
       k.notes_enc, k.updated_by, k.updated_at,
       (SELECT o.defectdojo FROM keyed o WHERE o.new_id = k.new_id AND o.defectdojo IS NOT NULL
        ORDER BY o.updated_at DESC LIMIT 1) AS defectdojo
FROM keyed k
ORDER BY k.new_id, k.edited DESC, k.updated_at DESC;

DELETE FROM finding_states;
INSERT INTO finding_states (finding_id, scan_id, category, entity_key, status, score_override, assignee, tags,
                            notes_enc, updated_by, updated_at, defectdojo)
SELECT finding_id, scan_id, category, entity_key, status, score_override, assignee, tags,
       notes_enc, updated_by, updated_at, defectdojo
FROM finding_states_merged;
