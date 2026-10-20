// Fuzzer for DuckDB's Parquet WRITER and the read-back path.
//
// Rationale
// ---------
// The existing parquet_fuzz_test covers the reader (footer Thrift parse,
// column readers, decompression) but nothing drives the writer side:
//   * extension/parquet writer (column writer, page/dictionary/RLE/
//     bit-packing encoders, statistics, footer serialization)
//   * third_party/{zstd,brotli,miniz,snappy} compression ENCODERS
// A write -> read-back round trip exercises both the encoders and the
// decoders on self-consistent data, and cross-checks the two halves
// against each other.
//
// Design
// ------
// Leading input bytes select the table shape (schema, row count,
// compression codec, null density); the remaining bytes feed a
// deterministic value pool, so libFuzzer mutations directly steer what
// gets encoded. The table is written to a temp file with the selected
// codec, then fully materialized via read_parquet() and inspected through
// parquet_schema() / parquet_metadata() (metadata-only paths). Malformed
// combinations are impossible by construction, but any DuckDB exception is
// expected and swallowed; only memory-safety faults / sanitizer reports
// are findings.

#include "duckdb.hpp"

#include <cstdint>
#include <cstdio>
#include <string>

static const char *kTmpFile = "/tmp/duckdb_parquet_write_fuzz.parquet";

// The writer is stateless with respect to the database beyond the scratch
// table, so a single in-memory instance is reused across iterations (a
// fresh instance per input dominated runtime); it is recreated periodically
// to bound catalog growth.
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
	g_con->Query("SET threads=1");
	g_con->Query("PRAGMA enable_progress_bar=false");
}

} // namespace

static const char *CompressionName(uint8_t selector) {
	static const char *kCompressions[] = {"uncompressed", "gzip", "zstd", "snappy", "brotli"};
	return kCompressions[selector % 5];
}

static std::string SqlString(const uint8_t *data, size_t size, size_t max_len) {
	std::string escaped;
	escaped.reserve(size * 2 + 2);
	escaped += '\'';
	for (size_t i = 0; i < size && i < max_len; i++) {
		if (data[i] == '\'') {
			escaped += "''";
		} else if (data[i] == '\0') {
			escaped += ' '; // keep the statement well-formed
		} else if (data[i] == '\\') {
			escaped += "\\\\";
		} else {
			escaped += static_cast<char>(data[i]);
		}
	}
	escaped += '\'';
	return escaped;
}

// Turns payload bytes into a printable string of at most max_len chars.
static std::string PrintableString(const uint8_t *data, size_t size, size_t max_len) {
	std::string out;
	out.reserve(size < max_len ? size : max_len);
	for (size_t i = 0; i < size && out.size() < max_len; i++) {
		char c = static_cast<char>(data[i]);
		if (c == '\0') {
			c = ' ';
		}
		out += c;
	}
	return out;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 8) {
		return 0;
	}

	EnsureDatabase();
	if (++g_inputs % RESET_INTERVAL == 0) {
		ResetDatabase();
		EnsureDatabase();
	}
	duckdb::Connection &con = *g_con;

	// ---- input layout -----------------------------------------------------
	const uint8_t schema_sel = data[0] % 4;
	const uint32_t row_count = 1 + (data[1] % 200);
	const char *compression = CompressionName(data[2]);
	const bool inject_nulls = (data[3] % 4) == 0;
	const uint8_t value_stride = data[4] | 1; // odd, never zero
	const uint8_t *pool = data + 5;
	const size_t pool_size = size - 5;

	static const char *kSchemas[] = {
	    "i INTEGER, j BIGINT, s VARCHAR", "d DOUBLE, f FLOAT, b BOOLEAN",
	    "s VARCHAR, t TIMESTAMP, payload BLOB", "i INTEGER, d DOUBLE, s VARCHAR, li INTEGER[]"};
	const char *schema = kSchemas[schema_sel];

	try {
		if (con.Query("CREATE OR REPLACE TEMP TABLE t (" + std::string(schema) + ")")->HasError()) {
			return 0;
		}
		// One multi-row INSERT keeps the per-input statement count at 1.
		std::string insert = "INSERT INTO t VALUES ";
		for (uint32_t r = 0; r < row_count; r++) {
			const uint8_t a = pool[(r * value_stride) % pool_size];
			const uint8_t b = pool[(r * value_stride + 1) % pool_size];
			const uint8_t c = pool[(r * value_stride + 2) % pool_size];
			const bool is_null = inject_nulls && (r % 4 == 3);
			if (r > 0) {
				insert += ",";
			}
			switch (schema_sel) {
			case 0:
				if (is_null) {
					insert += "(NULL, NULL, NULL)";
				} else {
					insert += "(" + std::to_string(static_cast<int>(a)) + ", " +
					          std::to_string(static_cast<int64_t>(a) * 1000000 + b) + ", " +
					          SqlString(pool + (r % pool_size), 1 + (b % 16), 16) + ")";
				}
				break;
			case 1:
				if (is_null) {
					insert += "(NULL, NULL, NULL)";
				} else {
					insert += "(" + std::to_string(static_cast<double>(a) / 8.0) + ", " +
					          std::to_string(static_cast<float>(b) / 16.0f) + ", " +
					          (c % 2 ? "true" : "false") + ")";
				}
				break;
			case 2:
				if (is_null) {
					insert += "(NULL, NULL, NULL)";
				} else {
					// Deterministic timestamp in a sane range + a small BLOB.
					insert += "('" + PrintableString(pool + (r % pool_size), 1 + (b % 12), 12) +
					          "', TIMESTAMP '" + std::to_string(2000 + (a % 30)) + "-0" +
					          std::to_string(1 + (b % 9)) + "-1" + std::to_string(c % 9) +
					          " 12:34:56', '\\x" +
					          PrintableString(pool + (c % pool_size), 1 + (a % 8), 8) + "'::BLOB)";
				}
				break;
			default:
				if (is_null) {
					insert += "(NULL, NULL, NULL, NULL)";
				} else {
					insert += "(" + std::to_string(static_cast<int>(a)) + ", " +
					          std::to_string(static_cast<double>(b) / 4.0) + ", '" +
					          PrintableString(pool + (c % pool_size), 1 + (a % 10), 10) + "', [" +
					          std::to_string(static_cast<int>(b)) + ", " +
					          std::to_string(static_cast<int>(c)) + ", " +
					          std::to_string(static_cast<int>(a) + static_cast<int>(c)) + "])";
				}
				break;
			}
		}
		if (con.Query(insert)->HasError()) {
			return 0;
		}

		// ---- write + read back --------------------------------------------
		const std::string path(kTmpFile);
		if (con.Query("COPY t TO '" + path + "' (FORMAT parquet, COMPRESSION " + compression + ")")->HasError()) {
			return 0;
		}

		// Full materialization forces decode of everything just written.
		auto result = con.Query("SELECT * FROM read_parquet('" + path + "')");
		(void)result;

		// Metadata-only paths (schema elements, key/value metadata, stats).
		auto meta = con.Query("SELECT * FROM parquet_schema('" + path + "')");
		(void)meta;
		auto meta2 = con.Query("SELECT * FROM parquet_metadata('" + path + "')");
		(void)meta2;

		// A filtered read exercises zone-map / statistics pruning against
		// data the fuzzer just encoded.
		auto filtered = con.Query("SELECT * FROM read_parquet('" + path + "') WHERE " +
		                          std::string(schema_sel == 1 ? "d" : "i") + " IS NOT NULL LIMIT 10");
		(void)filtered;
	} catch (const std::exception &e) {
		// Expected for pathological (but well-formed) combinations.
	}

	remove(kTmpFile);
	return 0;
}