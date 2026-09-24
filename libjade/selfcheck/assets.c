#include "selfcheck.h"

typedef struct {
    const char* name;
    const char* ticker;
    size_t ticker_len;
} ticker_test_case_t;

// clang-format off
static const ticker_test_case_t HOST_TICKER_TEST_CASES_VALID[] = {
    { "valid: ticker is at minimum", "ABC", strlen("ABC") },
    { "valid: ticker is at maximum", "AAAAAAAAAAAAAAAAAAAAAAAA", strlen("AAAAAAAAAAAAAAAAAAAAAAAA") },
    { "valid: ticker is alphanumeric", "SLFc229f", strlen("SLFc229f") },
    { "valid: punctuation is allowed", ".aA0-", strlen(".aA0-") },
    { "valid: null ticker is empty", NULL, 0 },
    { "valid: ticker is empty", "", strlen("") }
};

static const ticker_test_case_t HOST_TICKER_TEST_CASES_INVALID[] = {
    { "invalid-pointer: null ticker has length", NULL, ASSET_TICKER_MIN_LEN },
    { "invalid-length: ticker has one character", "A", strlen("A") },
    { "invalid-length: ticker is below minimum", "AB", strlen("AB") },
    { "invalid-length: ticker is too long", "AAAAAAAAAAAAAAAAAAAAAAAAA", strlen("AAAAAAAAAAAAAAAAAAAAAAAAA") },
    { "invalid-characters: ticker contains space", "AB CD", strlen("AB CD") },
    { "invalid-characters: ticker contains underscore", "AB_CD", strlen("AB_CD") },
    { "invalid-characters: ticker contains slash", "AB/CD", strlen("AB/CD") },
    { "invalid-characters: ticker contains control byte", "AB\001CD", strlen("AB\001CD") },
    { "invalid-characters: ticker contains null byte", "AB\0CD", strlen("AB\0CD") },
    { "invalid-characters: ticker contains utf-8", "AB\xc3\xa9", strlen("AB\xc3\xa9") }
};
// clang-format on

static bool run_ticker_test_case(const ticker_test_case_t* const test, bool expect_valid)
{
    JADE_LOGI("%s", test->name);
    if (is_valid_asset_ticker(test->ticker, test->ticker_len) != expect_valid) {
        FAIL();
    }
    return true;
}

static bool test_host_tickers(void)
{
    bool ret = true;

    for (size_t i = 0; i < sizeof(HOST_TICKER_TEST_CASES_VALID) / sizeof(HOST_TICKER_TEST_CASES_VALID[0]); ++i) {
        ret = ret && run_ticker_test_case(&HOST_TICKER_TEST_CASES_VALID[i], true);
    }

    for (size_t i = 0; i < sizeof(HOST_TICKER_TEST_CASES_INVALID) / sizeof(HOST_TICKER_TEST_CASES_INVALID[0]); ++i) {
        ret = ret && run_ticker_test_case(&HOST_TICKER_TEST_CASES_INVALID[i], false);
    }

    return ret;
}

static bool test_snapshot_tickers(void)
{
    static const char MAINNET_LONG_ID[] = "2953bce80bf102359b8dc1f716171b643e934da87e348764242968e60a39b25c";
    static const char MAINNET_NULL_ID[] = "00f70b9bb818ffbc84610501bcb686f616f4cf134f85936b5db11fa028fbe393";
    static const char TESTNET_LONG_ID[] = "5a1d5b6e0a75002466d9b4ce317fad2175157f5f68cd21f40786d479d55985b9";

    asset_info_t found = { 0 };
    if (!assets_get_info(NETWORK_LIQUID, NULL, 0, MAINNET_LONG_ID, &found) || !found.ticker
        || found.ticker_len != strlen("Sangiovese2") || strncmp(found.ticker, "Sangiovese2", found.ticker_len)) {
        FAIL();
    }

    memset(&found, 0, sizeof(found));
    if (!assets_get_info(NETWORK_LIQUID_TESTNET, NULL, 0, TESTNET_LONG_ID, &found) || !found.ticker
        || found.ticker_len != strlen("TESTASSET020723-1")
        || strncmp(found.ticker, "TESTASSET020723-1", found.ticker_len)) {
        FAIL();
    }

    memset(&found, 0, sizeof(found));
    if (!assets_get_info(NETWORK_LIQUID, NULL, 0, MAINNET_NULL_ID, &found) || !found.ticker
        || found.ticker_len != strlen(ASSET_EMPTY_TICKER)
        || strncmp(found.ticker, ASSET_EMPTY_TICKER, found.ticker_len)) {
        FAIL();
    }

    return true;
}

bool debug_selfcheck(jade_process_t* process)
{
    if (!test_host_tickers() || !test_snapshot_tickers()) {
        FAIL();
    }
    return true;
}