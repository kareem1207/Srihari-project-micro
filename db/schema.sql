-- PostgreSQL DDL generated from backend/models.py (python -m backend.cli is not required).

CREATE TABLE applications (
	id SERIAL NOT NULL, 
	name VARCHAR(255) NOT NULL, 
	exe_path VARCHAR(1024) NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	allowlisted BOOLEAN NOT NULL, 
	PRIMARY KEY (id)
);

CREATE INDEX ix_applications_name ON applications (name);

CREATE TABLE security_policies (
	id SERIAL NOT NULL, 
	name VARCHAR(128) NOT NULL, 
	policy_type VARCHAR(32) NOT NULL, 
	config JSON NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (name)
);

CREATE TABLE users (
	id SERIAL NOT NULL, 
	username VARCHAR(64) NOT NULL, 
	password_hash VARCHAR(255) NOT NULL, 
	role VARCHAR(16) NOT NULL, 
	is_active BOOLEAN NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (username)
);

CREATE TABLE audit_records (
	id SERIAL NOT NULL, 
	user_id INTEGER, 
	action VARCHAR(64) NOT NULL, 
	details TEXT NOT NULL, 
	ts TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES users (id)
);

CREATE TABLE devices (
	id SERIAL NOT NULL, 
	device_uid VARCHAR(64) NOT NULL, 
	name VARCHAR(128) NOT NULL, 
	os VARCHAR(128) NOT NULL, 
	user_id INTEGER, 
	status VARCHAR(16) NOT NULL, 
	agent_status VARCHAR(16) NOT NULL, 
	last_seen TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (device_uid), 
	FOREIGN KEY(user_id) REFERENCES users (id)
);

CREATE TABLE application_events (
	id SERIAL NOT NULL, 
	device_id INTEGER NOT NULL, 
	application_id INTEGER NOT NULL, 
	description TEXT NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	severity VARCHAR(16) NOT NULL, 
	reviewed BOOLEAN NOT NULL, 
	ts TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(device_id) REFERENCES devices (id), 
	FOREIGN KEY(application_id) REFERENCES applications (id)
);

CREATE INDEX ix_appev_device_ts ON application_events (device_id, ts);

CREATE TABLE network_events (
	id SERIAL NOT NULL, 
	device_id INTEGER NOT NULL, 
	src_ip VARCHAR(64), 
	dst_ip VARCHAR(64), 
	protocol VARCHAR(16), 
	source VARCHAR(32) NOT NULL, 
	classification VARCHAR(16) NOT NULL, 
	ts TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(device_id) REFERENCES devices (id)
);

CREATE INDEX ix_netev_device_ts ON network_events (device_id, ts);

CREATE TABLE security_logs (
	id SERIAL NOT NULL, 
	device_id INTEGER, 
	source VARCHAR(32) NOT NULL, 
	event_type VARCHAR(48) NOT NULL, 
	severity VARCHAR(16) NOT NULL, 
	description TEXT NOT NULL, 
	ts TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(device_id) REFERENCES devices (id)
);

CREATE INDEX ix_log_sev ON security_logs (severity);

CREATE INDEX ix_log_ts ON security_logs (ts);

CREATE TABLE intrusion_alerts (
	id SERIAL NOT NULL, 
	device_id INTEGER NOT NULL, 
	network_event_id INTEGER, 
	detection_result VARCHAR(16) NOT NULL, 
	attack_category VARCHAR(32) NOT NULL, 
	severity VARCHAR(16) NOT NULL, 
	confidence FLOAT, 
	model VARCHAR(64) NOT NULL, 
	dedup_key VARCHAR(128) NOT NULL, 
	occurrences INTEGER NOT NULL, 
	reviewed BOOLEAN NOT NULL, 
	ts TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(device_id) REFERENCES devices (id), 
	FOREIGN KEY(network_event_id) REFERENCES network_events (id)
);

CREATE INDEX ix_alert_ts ON intrusion_alerts (ts);

CREATE INDEX ix_alert_dedup ON intrusion_alerts (device_id, dedup_key, ts);
