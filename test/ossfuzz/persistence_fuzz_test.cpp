// Fuzzer for DuckDB's persistence layer: the block manager, WAL, checkpoints
// and catalog (de)serialization.

#include "duckdb.hpp"
#include "duckdb/common/string_util.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unordered_set>

static const char *kDbFile = "/tmp/duckdb_persistence_fuzz.db";

namespace {

duckdb::DuckDB *g_db = nullptr;
duckdb::Connection *g_con = nullptr;
size_t g_inputs = 0;

constexpr size_t REOPEN_INTERVAL = 64;

void ResetDatabase() {
	if (g_con) {
		delete g_con;
		g_con = nullptr;
	}
	if (g_db) {
		delete g_db;
		g_db = nullptr;
	}
}

void EnsureDatabase() {
	if (g_db) {
		return;
	}
	g_db = new duckdb::DuckDB(kDbFile);
	g_con = new duckdb::Connection(*g_db);
	g_con->Query("SET threads=1");
	g_con->Query("SET enable_progress_bar=false");
	g_con->Query("SET max_expression_depth=50");
	g_con->Query("SET checkpoint_threshold='1GB'"); // we checkpoint explicitly
}

std::string SqlString(const uint8_t *data, size_t size, size_t max_len) {
	std::string escaped;
	escaped.reserve(size * 2 + 2);
	escaped += '\'';
	for (size_t i = 0; i < size && i < max_len; i++) {
		if (data[i] == '\'') {
			escaped += "''";
		} else if (data[i] == '\0') {
			escaped += ' ';
		} else {
			escaped += static_cast<char>(data[i]);
		}
	}
	escaped += '\'';
	return escaped;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 4) {
		return 0;
	}

	// Remove stale database files from a previous process run so each
	// fuzzing session starts from a clean slate.
	if (g_inputs == 0) {
		remove(kDbFile);
		remove((std::string(kDbFile) + ".wal").c_str());
	}

	EnsureDatabase();
	if (++g_inputs % REOPEN_INTERVAL == 0) {
		ResetDatabase();
		EnsureDatabase(); // reopen: WAL replay + catalog load from blocks
	}
	duckdb::Connection &con = *g_con;

	const uint8_t op = data[0] % 8;
	const uint8_t *payload = data + 1;
	const size_t payload_size = size - 1;
	const uint8_t a = payload[0];
	const uint8_t b = payload[1 % payload_size];

	// A rotating set of table names keeps catalog entries bounded while
	// still building up persistent state that later inputs must recover.
	const std::string table = "t" + std::to_string(a % 4);

	std::string sql;
	switch (op) {
	case 0:
		// Raw SQL batch (storage-flavored seeds come from the corpus).
		sql.assign(reinterpret_cast<const char *>(payload), payload_size > 4096 ? 4096 : payload_size);
		break;
	case 1: {
		static const char *kColumns[] = {"i INTEGER", "i INTEGER, s VARCHAR", "i BIGINT, d DOUBLE, b BOOLEAN",
		                                 "s VARCHAR, payload BLOB"};
		sql = "CREATE TABLE IF NOT EXISTS " + table + " (" + kColumns[b % 4] + ")";
		break;
	}
	case 2: {
		// Bounded multi-row insert; rows land in the WAL until checkpoint.
		std::string values;
		for (int r = 0; r < 8; r++) {
			if (r > 0) {
				values += ",";
			}
			values += "(" + std::to_string(static_cast<int>(payload[r % payload_size])) + ", " +
			          SqlString(payload + r, payload_size - r < 8 ? payload_size - r : 8, 8) + ")";
		}
		sql = "INSERT OR REPLACE INTO " + table + " SELECT * FROM (VALUES " + values + ") __fuzz(v1, v2)";
		break;
	}
	case 3:
		sql = "UPDATE " + table + " SET i = " + std::to_string(static_cast<int>(b)) + " WHERE i = " +
		      std::to_string(static_cast<int>(a));
		break;
	case 4:
		sql = "DELETE FROM " + table + " WHERE i = " + std::to_string(static_cast<int>(a));
		break;
	case 5:
		sql = ((b % 2) ? "CREATE INDEX IF NOT EXISTS idx_" : "DROP INDEX IF EXISTS idx_") + table + "_" +
		      std::to_string(b % 4) + // name is per-table for CREATE
		      std::string((b % 2) ? " ON " + table + " (i)" : "");
		break;
	case 6:
		sql = ((a % 2) ? "ALTER TABLE " + table + " ADD COLUMN IF NOT EXISTS extra_" + std::to_string(b % 4) +
		                     " VARCHAR"
		               : "ALTER TABLE " + table + " DROP COLUMN IF EXISTS extra_" + std::to_string(b % 4));
		break;
	default:
		sql = "CHECKPOINT";
		break;
	}

	std::unordered_set<std::string> internal_error_messages = {"Unoptimized Result differs from original result!",
	                                                           "INTERNAL"};
	bool internal_error = false;
	try {
		auto result = con.Query(sql);
		if (result->HasError()) {
			for (auto &internal_error_message : internal_error_messages) {
				if (duckdb::StringUtil::Contains(result->GetError(), internal_error_message)) {
					internal_error = true;
					break;
				}
			}
		}
	} catch (std::exception &e) {
	}

	// Force WAL -> block flushes regularly so block-manager and metadata
	// writer paths run against fuzzer-controlled content.
	if (!internal_error && g_inputs % 8 == 0) {
		try {
			con.Query("CHECKPOINT");
		} catch (std::exception &e) {
		}
	}

	if (internal_error) {
		// libFuzzer ignores the harness return value; report loudly.
		ResetDatabase();
		abort();
	}
	return 0;
}
