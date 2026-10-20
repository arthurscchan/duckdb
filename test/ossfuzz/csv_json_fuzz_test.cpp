// Fuzzer for DuckDB CSV and JSON parsing pipelines.
// Exercises read_csv_auto (CSV sniffer, state machine, type detection)
// and JSON functions (json_valid, json_extract, json_type).

#include "duckdb.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

static const char *TMPFILE = "/tmp/duckdb_fuzz_data";

// Constructing a fresh DuckDB instance per input dominated the
// runtime (~5 exec/s), so a single in-memory instance is reused across
// inputs and recreated periodically to bound catalog/heap growth. This keeps
// the fuzzer focused on the CSV/JSON pipelines under test.
namespace {

duckdb::DuckDB *g_db = nullptr;
duckdb::Connection *g_con = nullptr;
size_t g_inputs = 0;

constexpr size_t RESET_INTERVAL = 4096;

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
	g_db = new duckdb::DuckDB(nullptr);
	g_con = new duckdb::Connection(*g_db);
	// Disable progress bar / parallelism and set memory/row limits to
	// prevent resource exhaustion.
	g_con->Query("SET threads=1");
	g_con->Query("SET enable_progress_bar=false");
	g_con->Query("SET max_expression_depth=50");
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 2) {
		return 0;
	}

	// First byte selects which code path to exercise.
	uint8_t selector = data[0];
	const uint8_t *payload = data + 1;
	size_t payload_size = size - 1;

	// Limit payload to avoid excessive processing time.
	if (payload_size > 8192) {
		payload_size = 8192;
	}

	EnsureDatabase();
	if (++g_inputs % RESET_INTERVAL == 0) {
		ResetDatabase();
		EnsureDatabase();
	}
	duckdb::Connection &con = *g_con;

	try {
		switch (selector % 4) {
		case 0: {
			// CSV auto-detection and parsing via read_csv_auto.
			// Exercises: CSVSniffer, CSVStateMachine, StringValueScanner,
			// type detection, dialect detection.
			FILE *f = fopen(TMPFILE, "wb");
			if (!f)
				return 0;
			fwrite(payload, 1, payload_size, f);
			fclose(f);
			con.Query("SELECT * FROM read_csv_auto('" + std::string(TMPFILE) + "', sample_size=1) LIMIT 10");
			break;
		}
		case 1: {
			// CSV with explicit options to exercise different scanner paths.
			FILE *f = fopen(TMPFILE, "wb");
			if (!f)
				return 0;
			fwrite(payload, 1, payload_size, f);
			fclose(f);
			con.Query("SELECT * FROM read_csv('" + std::string(TMPFILE) +
			          "', columns={'c1': 'VARCHAR', 'c2': 'VARCHAR', 'c3': 'VARCHAR'}, "
			          "auto_detect=false, header=false, sample_size=1) LIMIT 10");
			break;
		}
		case 2: {
			// JSON validation and extraction functions.
			// Exercises: yyjson parser, JSONCommon::ReadDocumentUnsafe,
			// json_valid, json_type, json_extract.
			std::string str_payload(reinterpret_cast<const char *>(payload), payload_size);
			// Escape single quotes for SQL safety.
			std::string escaped;
			escaped.reserve(str_payload.size() * 2);
			for (char c : str_payload) {
				if (c == '\'') {
					escaped += "''";
				} else if (c == '\0') {
					// Skip null bytes in SQL strings.
					continue;
				} else {
					escaped += c;
				}
			}
			con.Query("SELECT json_valid('" + escaped + "')");
			con.Query("SELECT json_type('" + escaped + "')");
			con.Query("SELECT json_extract('" + escaped + "', '$')");
			break;
		}
		case 3: {
			// JSON file reading via read_json_auto.
			// Exercises: JSONReader, JSON scanning, auto schema detection.
			FILE *f = fopen(TMPFILE, "wb");
			if (!f)
				return 0;
			fwrite(payload, 1, payload_size, f);
			fclose(f);
			con.Query("SELECT * FROM read_json_auto('" + std::string(TMPFILE) +
			          "', maximum_sample_files=1, sample_size=1) LIMIT 10");
			break;
		}
		}
	} catch (std::exception &e) {
		// Expected: malformed input will throw.
	}

	remove(TMPFILE);
	return 0;
}
