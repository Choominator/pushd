#include <stdio.h>
#include <stdlib.h>

#include <sqlite3.h>

#include "config.h"
#include "database.h"
#include "cmdopt.h"

static char const *database_path = CONFIG_DATABASE_PATH;
static sqlite3 *database_sqlite3 = NULL;
static sqlite3_stmt *database_sqlite3_stmt_transaction_begin = NULL;
static sqlite3_stmt *database_sqlite3_stmt_transaction_rollback = NULL;
static sqlite3_stmt *database_sqlite3_stmt_transaction_commit = NULL;
static sqlite3_stmt *database_sqlite3_stmt_select_group_devices = NULL;
static sqlite3_stmt *database_sqlite3_stmt_select_group = NULL;
static sqlite3_stmt *database_sqlite3_stmt_insert_group = NULL;
static sqlite3_stmt *database_sqlite3_stmt_select_device = NULL;
static sqlite3_stmt *database_sqlite3_stmt_insert_device = NULL;
static sqlite3_stmt *database_sqlite3_stmt_insert_rel = NULL;
static sqlite3_stmt *database_sqlite3_stmt_delete_device = NULL;

static int database_transaction_begin(void);
static void database_transaction_rollback(void);
static int database_transaction_commit(void);
static sqlite3_int64 database_generic_select(char const *value, size_t len, sqlite3_stmt *statement);
static sqlite3_int64 database_generic_insert(char const *value, size_t len, sqlite3_stmt *statement);
static int database_insert_rel(sqlite3_int64 group_id, sqlite3_int64 device_id);
static sqlite3_stmt *database_prepare_statement(char const *sql);
static void database_cleanup(void);

void database_cmdopt(void) {
    cmdopt_register('d', "Path to the database", 0, NULL, &database_path);
}

void database_init(void) {
    atexit(database_cleanup);
    int status = sqlite3_open(database_path, &database_sqlite3);
    if (status != SQLITE_OK) {
        fprintf(stderr, "Unable to open the database: %s\n", sqlite3_errmsg(database_sqlite3));
        exit(EXIT_FAILURE);
    }
    char const *sql =
    "pragma foreign_keys = on;"
    "create table if not exists groups (id integer not null primary key, name text not null unique);"
    "create table if not exists devices (id integer not null primary key, token text not null unique);"
    "create table if not exists group_devices (group_id integer not null, device_id integer not null, primary key (group_id, device_id), foreign key (group_id) references groups(id) on delete cascade on update restrict, foreign key (device_id) references devices(id) on delete cascade on update restrict) without rowid;";
    char *errmsg;
    status = sqlite3_exec(database_sqlite3, sql, NULL, NULL, &errmsg);
    if (status != SQLITE_OK) {
        fprintf(stderr, "Unable to create tables in the database: %s\n", errmsg);
        sqlite3_free(errmsg);
        exit(EXIT_FAILURE);
    }
    sql = "begin transaction";
    database_sqlite3_stmt_transaction_begin = database_prepare_statement(sql);
    sql = "rollback transaction";
    database_sqlite3_stmt_transaction_rollback = database_prepare_statement(sql);
    sql = "commit transaction";
    database_sqlite3_stmt_transaction_commit = database_prepare_statement(sql);
    sql = "select token from devices inner join group_devices on devices.id = group_devices.device_id inner join groups on group_devices.group_id = groups.id where groups.name = ?";
    database_sqlite3_stmt_select_group_devices = database_prepare_statement(sql);
    sql = "select id from groups where name = ?";
    database_sqlite3_stmt_select_group = database_prepare_statement(sql);
    sql = "insert into groups (name) values (?)";
    database_sqlite3_stmt_insert_group = database_prepare_statement(sql);
    sql = "select id from devices where token = ?";
    database_sqlite3_stmt_select_device = database_prepare_statement(sql);
    sql = "insert into devices (token) values (?)";
    database_sqlite3_stmt_insert_device = database_prepare_statement(sql);
    sql = "insert or ignore into group_devices (group_id, device_id) values (?, ?)";
    database_sqlite3_stmt_insert_rel = database_prepare_statement(sql);
    sql = "delete from devices where token = ?";
    database_sqlite3_stmt_delete_device = database_prepare_statement(sql);
}

int database_insert_group_device(char const *group, size_t group_len, char const *device, size_t device_len) {
    if (database_transaction_begin() < 0) return -1;
    sqlite3_int64 group_id = database_generic_select(group, group_len, database_sqlite3_stmt_select_group);
    if (group_id == 0) group_id = database_generic_insert(group, group_len, database_sqlite3_stmt_insert_group);
    if (group_id < 0) goto transaction;
    sqlite3_int64 device_id = database_generic_select(device, device_len, database_sqlite3_stmt_select_device);
    if (device_id == 0) device_id = database_generic_insert(device, device_len, database_sqlite3_stmt_insert_device);
    if (device_id < 0) goto transaction;
    if (database_insert_rel(group_id, device_id) < 0) goto transaction;
    if (database_transaction_commit() < 0) goto transaction;
    return 0;
transaction:
    database_transaction_rollback();
    return -1;
}

int database_select_group_devices(char const *group, size_t group_len) {
    if (sqlite3_bind_text(database_sqlite3_stmt_select_group_devices, 1, group, group_len, SQLITE_TRANSIENT) != SQLITE_OK) return -1;
    return 0;
}

int database_next_device(char const **device, size_t *device_len) {
    int status = sqlite3_step(database_sqlite3_stmt_select_group_devices);
    if (status == SQLITE_ROW) {
        *device = (char const *) sqlite3_column_text(database_sqlite3_stmt_select_group_devices, 0);
        *device_len = sqlite3_column_bytes(database_sqlite3_stmt_select_group_devices, 0);
        return 0;
    }
    int ret = 0;
    if (status != SQLITE_DONE) ret = -1;
    sqlite3_reset(database_sqlite3_stmt_select_group_devices);
    return ret;
}

int database_delete_device(char const *device, size_t device_len) {
    if (sqlite3_bind_text(database_sqlite3_stmt_delete_device, 1, device, device_len, SQLITE_TRANSIENT) != SQLITE_OK) return -1;
    int ret = 0;
    if (sqlite3_step(database_sqlite3_stmt_delete_device) != SQLITE_DONE) ret = -1;
    sqlite3_reset(database_sqlite3_stmt_delete_device);
    return ret;
}

static int database_transaction_begin(void) {
    int ret = 0;
    if (sqlite3_step(database_sqlite3_stmt_transaction_begin) != SQLITE_DONE) ret = -1;
    sqlite3_reset(database_sqlite3_stmt_transaction_begin);
    return ret;
}

static void database_transaction_rollback(void) {
    sqlite3_step(database_sqlite3_stmt_transaction_rollback);
    sqlite3_reset(database_sqlite3_stmt_transaction_rollback);
}

static int database_transaction_commit(void) {
    int ret = 0;
    if (sqlite3_step(database_sqlite3_stmt_transaction_commit) != SQLITE_DONE) ret = -1;
    sqlite3_reset(database_sqlite3_stmt_transaction_commit);
    return ret;
}

static sqlite3_int64 database_generic_select(char const *value, size_t len, sqlite3_stmt *statement) {
    if (sqlite3_bind_text(statement, 1, value, len, SQLITE_TRANSIENT) != SQLITE_OK) return -1;
    sqlite3_int64 ret = -1;
    int status = sqlite3_step(statement);
    if (status != SQLITE_ROW) goto query;
    ret = sqlite3_column_int64(statement, 0);
query:
    sqlite3_reset(statement);
    if (status == SQLITE_DONE) return 0;
    return ret;
}

static sqlite3_int64 database_generic_insert(char const *value, size_t len, sqlite3_stmt *statement) {
    if (sqlite3_bind_text(statement, 1, value, len, SQLITE_TRANSIENT) != SQLITE_OK) return -1;
    sqlite3_int64 ret = -1;
    if (sqlite3_step(statement) != SQLITE_DONE) goto query;
    ret = sqlite3_last_insert_rowid(database_sqlite3);
query:
    sqlite3_reset(statement);
    return ret;
}

static int database_insert_rel(sqlite3_int64 group_id, sqlite3_int64 device_id) {
    if (sqlite3_bind_int64(database_sqlite3_stmt_insert_rel, 1, group_id) != SQLITE_OK) return -1;
    if (sqlite3_bind_int64(database_sqlite3_stmt_insert_rel, 2, device_id) != SQLITE_OK) return -1;
    int ret = 0;
    if (sqlite3_step(database_sqlite3_stmt_insert_rel) != SQLITE_DONE) ret = -1;
    sqlite3_reset(database_sqlite3_stmt_insert_rel);
    return ret;
}

static sqlite3_stmt *database_prepare_statement(char const *sql) {
    sqlite3_stmt *statement;
    int status = sqlite3_prepare_v2(database_sqlite3, sql, -1, &statement, NULL);
    if (status != SQLITE_OK) {
        fprintf(stderr, "Unable to prepare a database query statement: %s\n", sqlite3_errmsg(database_sqlite3));
        exit(EXIT_FAILURE);
    }
    return statement;
}

static void database_cleanup(void) {
    if (database_sqlite3_stmt_transaction_begin) sqlite3_finalize(database_sqlite3_stmt_transaction_begin);
    if (database_sqlite3_stmt_transaction_rollback) sqlite3_finalize(database_sqlite3_stmt_transaction_rollback);
    if (database_sqlite3_stmt_transaction_commit) sqlite3_finalize(database_sqlite3_stmt_transaction_commit);
    if (database_sqlite3_stmt_select_group_devices) sqlite3_finalize(database_sqlite3_stmt_select_group_devices);
    if (database_sqlite3_stmt_select_group) sqlite3_finalize(database_sqlite3_stmt_select_group);
    if (database_sqlite3_stmt_insert_group) sqlite3_finalize(database_sqlite3_stmt_insert_group);
    if (database_sqlite3_stmt_select_device) sqlite3_finalize(database_sqlite3_stmt_select_device);
    if (database_sqlite3_stmt_insert_device) sqlite3_finalize(database_sqlite3_stmt_insert_device);
    if (database_sqlite3_stmt_insert_rel) sqlite3_finalize(database_sqlite3_stmt_insert_rel);
    if (database_sqlite3_stmt_delete_device) sqlite3_finalize(database_sqlite3_stmt_delete_device);
    if (database_sqlite3) sqlite3_close(database_sqlite3);
}
