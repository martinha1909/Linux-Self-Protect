#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include "include/QueryHistory.hpp"

static void _print_usage()
{
    printf("Usage: ./attempts_history [start_date] [end_date]\n"
           "\tstart_date:\n"
           "\t\tFormat: YYYY-MM-DD\n"
           "\tend_date:\n"
           "\t\tFormat: YYYY-MM-DD\n"
           "\tif both start_date and end_date are -1, all attempt records are returned\n"
           "\tif start_date and <end_date> not provided, all attempt records are returned\n"
           "\tif end_date is -1, all attempts after <start_date> is returned\n"
           "\tif start_date is -1, all attempts before <end_date> is returned\n");
}

static void _date_time_fmt_check(const char* input, int* year, int* month, int* day)
{
    int chars_parsed;
    if (sscanf(input, "%4d-%2d-%2d%n", year, month, day, &chars_parsed) != 3) {
        printf("Format error: missing either day, month, or year\n");
        exit(EXIT_FAILURE);
    }

    if (input[chars_parsed] != '\0') {
        printf("Format error: incorrect start date or end date string\n");
        exit(EXIT_FAILURE);
    }
}

static inline long _ts_tz_offset_get()
{
    time_t t = time(NULL);
    struct tm tm = {};

    localtime_r(&t, &tm);

    return tm.tm_gmtoff;
}

static inline int _ts_isdst_get()
{
    time_t t = time(NULL);
    struct tm tm = {};

    localtime_r(&t, &tm);

    return tm.tm_isdst;
}

static inline void _ts_set(struct tm* tm, int year, int month, int day)
{
    tm->tm_year = year - 1900;
    tm->tm_mon = month - 1;
    tm->tm_mday = day;
    tm->tm_gmtoff = _ts_tz_offset_get();
    tm->tm_isdst = _ts_isdst_get();
}

int main(int argc, char* argv[])
{
    int opt;
    time_t start = -1;
    time_t end = -1;
    std::vector<query_history_record_t*> events;
    QueryHistory history;

    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
            case 'h':
                _print_usage();
                exit(EXIT_SUCCESS);
            case '?':
            default:
                printf("Usage: ./attempts_history [-h]\n");
                exit(EXIT_FAILURE);
        }
    }

    if (argc == 2 || argc > 3) {
        _print_usage();
        exit(EXIT_FAILURE);
    }

    if (argc == 3) {
        int day;
        int month;
        int year;

        if (argv[1] != NULL) {
            struct tm tm;

            memset(&tm, 0, sizeof(tm));

            _date_time_fmt_check(argv[1], &year, &month, &day);
            _ts_set(&tm, year, month, day);

            start = mktime(&tm);
        }
        if (argv[2] != NULL) {
            struct tm tm;

            memset(&tm, 0, sizeof(tm));

            _date_time_fmt_check(argv[2], &year, &month, &day);
            _ts_set(&tm, year, month, day);

            end = mktime(&tm);
        }

        if (start == end) {
            /* if they provide the same date as start and end, get all records from 12 am to 11:59 pm that day*/
            end = end + 3600 * 24 - 1;
        }
    }

    events = history.getEventsFromDb(start, end);

    if (!events.empty()) {
        history.printRecords(events);
        history.deallocRecordList(events);
    } else {
        printf("No attempts found.\n");
    }
}