-- ================================================================
-- Titan Verifier — Supabase Schema
-- ================================================================
-- Dieses SQL in Supabase SQL-Editor einfügen und ausführen.
-- Erstellt alle 6 Tabellen als Online-Spiegel der lokalen SQLite.
-- ================================================================

-- 1. Identities (Hardware-DNA)
CREATE TABLE IF NOT EXISTS identities (
    id                  BIGINT PRIMARY KEY,
    name                TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'ready',
    notes               TEXT,
    serial              TEXT NOT NULL,
    boot_serial         TEXT NOT NULL,
    imei1               TEXT NOT NULL,
    imei2               TEXT NOT NULL,
    gsf_id              TEXT NOT NULL,
    android_id          TEXT NOT NULL,
    wifi_mac            TEXT NOT NULL,
    widevine_id         TEXT NOT NULL,
    imsi                TEXT NOT NULL,
    sim_serial          TEXT NOT NULL,
    operator_name       TEXT DEFAULT 'o2-de',
    phone_number        TEXT NOT NULL,
    sim_operator        TEXT DEFAULT '26207',
    sim_operator_name   TEXT DEFAULT 'o2 - de',
    voicemail_number    TEXT DEFAULT '+4917610',
    build_id            TEXT,
    build_fingerprint   TEXT,
    security_patch      TEXT,
    build_incremental   TEXT,
    build_description   TEXT,
    advertising_id      TEXT,
    bluetooth_mac       TEXT,
    last_public_ip      TEXT,
    last_ip_service     TEXT,
    last_ip_at          TEXT,
    last_audit_score    INTEGER,
    last_audit_at       TEXT,
    last_audit_detail   TEXT,
    total_audits        INTEGER DEFAULT 0,
    created_at          TEXT DEFAULT (to_char(now(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    updated_at          TEXT,
    last_used_at        TEXT,
    usage_count         INTEGER DEFAULT 0
);

-- 2. Profiles (Vault / Account Management)
CREATE TABLE IF NOT EXISTS profiles (
    id                      BIGINT PRIMARY KEY,
    identity_id             BIGINT REFERENCES identities(id) ON DELETE CASCADE,
    name                    TEXT NOT NULL,
    status                  TEXT DEFAULT 'warmup',
    notes                   TEXT,
    tiktok_username         TEXT,
    tiktok_email            TEXT,
    tiktok_password         TEXT,
    tiktok_followers        INTEGER DEFAULT 0,
    tiktok_following        INTEGER DEFAULT 0,
    tiktok_likes            INTEGER DEFAULT 0,
    tiktok_install_id       TEXT,
    instagram_username      TEXT,
    instagram_email         TEXT,
    instagram_password      TEXT,
    youtube_username        TEXT,
    youtube_email           TEXT,
    youtube_password        TEXT,
    snapchat_username       TEXT,
    snapchat_email          TEXT,
    snapchat_password       TEXT,
    google_email            TEXT,
    google_password         TEXT,
    contact_email           TEXT,
    contact_password        TEXT,
    proxy_ip                TEXT,
    proxy_type              TEXT DEFAULT 'none',
    proxy_username          TEXT,
    proxy_password          TEXT,
    backup_status           TEXT DEFAULT 'none',
    backup_path             TEXT,
    backup_size_bytes       INTEGER,
    backup_created_at       TEXT,
    gms_backup_status       TEXT DEFAULT 'none',
    gms_backup_path         TEXT,
    gms_backup_size         INTEGER,
    gms_backup_at           TEXT,
    accounts_backup_status  TEXT DEFAULT 'none',
    accounts_backup_path    TEXT,
    accounts_backup_at      TEXT,
    created_at              TEXT DEFAULT (to_char(now(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    updated_at              TEXT,
    last_switch_at          TEXT,
    switch_count            INTEGER DEFAULT 0,
    last_active_at          TEXT
);

-- 3. Flow History (Audit-Trail)
CREATE TABLE IF NOT EXISTS flow_history (
    id                  BIGINT PRIMARY KEY,
    identity_id         BIGINT REFERENCES identities(id),
    profile_id          BIGINT REFERENCES profiles(id),
    flow_type           TEXT NOT NULL,
    status              TEXT DEFAULT 'running',
    started_at          TEXT NOT NULL,
    finished_at         TEXT,
    duration_ms         INTEGER,
    generated_serial    TEXT,
    generated_imei      TEXT,
    public_ip           TEXT,
    ip_service          TEXT,
    audit_score         INTEGER,
    audit_detail        TEXT,
    steps_json          TEXT,
    error               TEXT,
    created_at          TEXT DEFAULT (to_char(now(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);

-- 4. IP History
CREATE TABLE IF NOT EXISTS ip_history (
    id                  BIGINT PRIMARY KEY,
    identity_id         BIGINT REFERENCES identities(id),
    profile_id          BIGINT REFERENCES profiles(id),
    public_ip           TEXT NOT NULL,
    ip_service          TEXT,
    connection_type     TEXT DEFAULT 'unknown',
    flow_type           TEXT,
    detected_at         TEXT DEFAULT (to_char(now(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);

-- 5. Audit History
CREATE TABLE IF NOT EXISTS audit_history (
    id                  BIGINT PRIMARY KEY,
    identity_id         BIGINT REFERENCES identities(id),
    flow_id             BIGINT REFERENCES flow_history(id),
    score_percent       INTEGER NOT NULL,
    total_checks        INTEGER NOT NULL,
    passed_checks       INTEGER NOT NULL,
    failed_checks       INTEGER NOT NULL,
    checks_json         TEXT NOT NULL,
    error               TEXT,
    created_at          TEXT DEFAULT (to_char(now(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);

-- 6. Profile Logs (HookGuard Snapshots)
CREATE TABLE IF NOT EXISTS profile_logs (
    id                  BIGINT PRIMARY KEY,
    profile_id          BIGINT REFERENCES profiles(id) ON DELETE CASCADE,
    identity_id         BIGINT REFERENCES identities(id) ON DELETE SET NULL,
    trigger             TEXT NOT NULL,
    live_summary_json   TEXT,
    live_api_count      INTEGER DEFAULT 0,
    live_spoofed_pct    REAL,
    hookguard_json      TEXT,
    hook_count          TEXT,
    bridge_intact       INTEGER,
    heartbeat_ok        INTEGER,
    leaks_detected      INTEGER DEFAULT 0,
    kill_events_json    TEXT,
    kill_event_count    INTEGER DEFAULT 0,
    captured_at         TEXT DEFAULT (to_char(now(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);

-- ================================================================
-- Row Level Security: Alles öffentlich lesbar (anon key)
-- ================================================================
ALTER TABLE identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE flow_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE ip_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE profile_logs ENABLE ROW LEVEL SECURITY;

-- Lese-Zugriff für anon
CREATE POLICY "anon_read_identities" ON identities FOR SELECT USING (true);
CREATE POLICY "anon_read_profiles" ON profiles FOR SELECT USING (true);
CREATE POLICY "anon_read_flow_history" ON flow_history FOR SELECT USING (true);
CREATE POLICY "anon_read_ip_history" ON ip_history FOR SELECT USING (true);
CREATE POLICY "anon_read_audit_history" ON audit_history FOR SELECT USING (true);
CREATE POLICY "anon_read_profile_logs" ON profile_logs FOR SELECT USING (true);

-- Schreib-Zugriff für anon (INSERT/UPDATE via REST API vom Gerät)
CREATE POLICY "anon_write_identities" ON identities FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "anon_write_profiles" ON profiles FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "anon_write_flow_history" ON flow_history FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "anon_write_ip_history" ON ip_history FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "anon_write_audit_history" ON audit_history FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "anon_write_profile_logs" ON profile_logs FOR ALL USING (true) WITH CHECK (true);

-- ================================================================
-- Indizes
-- ================================================================
CREATE INDEX IF NOT EXISTS idx_identities_status ON identities(status);
CREATE INDEX IF NOT EXISTS idx_profiles_identity ON profiles(identity_id);
CREATE INDEX IF NOT EXISTS idx_profiles_status ON profiles(status);
CREATE INDEX IF NOT EXISTS idx_flow_type_status ON flow_history(flow_type, status);
CREATE INDEX IF NOT EXISTS idx_flow_time ON flow_history(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_ip_ip ON ip_history(public_ip);
CREATE INDEX IF NOT EXISTS idx_profile_logs_profile ON profile_logs(profile_id);
CREATE INDEX IF NOT EXISTS idx_profile_logs_time ON profile_logs(captured_at DESC);
