#include <stdio.h>
#include <stdlib.h>

#include <sqlite3.h>
#include <event2/event.h>

#include "config.h"
#include "cmdopt.h"
#include "logger.h"
#include "database.h"

enum database_flags {
    DATABASE_FLAGS_NONE,
    DATABASE_FLAGS_TRANSACTION = 1 << 0
};

static enum database_flags database_flags = DATABASE_FLAGS_NONE;
static char const *database_path = CONFIG_DATABASE_PATH;
static sqlite3 *database_sqlite3 = NULL;
static sqlite3_stmt *database_sqlite3_stmt_transaction_begin = NULL;
static sqlite3_stmt *database_sqlite3_stmt_transaction_rollback = NULL;
static sqlite3_stmt *database_sqlite3_stmt_transaction_commit = NULL;
static sqlite3_stmt *database_sqlite3_stmt_group_list_clear = NULL;
static sqlite3_stmt *database_sqlite3_stmt_group_list_add = NULL;
static sqlite3_stmt *database_sqlite3_stmt_devices_by_group_list = NULL;
static sqlite3_stmt *database_sqlite3_stmt_device_by_token = NULL;
static sqlite3_stmt *database_sqlite3_stmt_device_add = NULL;
static sqlite3_stmt *database_sqlite3_stmt_group_by_name = NULL;
static sqlite3_stmt *database_sqlite3_stmt_group_add = NULL;
static sqlite3_stmt *database_sqlite3_stmt_subscription_add = NULL;
static sqlite3_stmt *database_sqlite3_stmt_device_del = NULL;

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
    "create table if not exists devices (id integer not null primary key, token text not null unique);"
    "create table if not exists groups (id integer not null primary key, name text not null unique);"
    "create table if not exists subscriptions (device_id integer not null, group_id integer not null, primary key (device_id, group_id), foreign key (device_id) references devices(id) on delete cascade on update restrict, foreign key (group_id) references groups(id) on delete cascade on update restrict) without rowid;"
    "create temporary table group_list (name text not null primary key) without rowid;";
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
    sql = "delete from group_list";
    database_sqlite3_stmt_group_list_clear = database_prepare_statement(sql);
    sql = "insert or ignore into group_list (name) values (?)";
    database_sqlite3_stmt_group_list_add = database_prepare_statement(sql);
    sql = "select distinct token from devices inner join subscriptions on devices.id = subscriptions.device_id inner join groups on subscriptions.group_id = groups.id where groups.name in group_list";
    database_sqlite3_stmt_devices_by_group_list = database_prepare_statement(sql);
    sql = "select id from devices where token = ?";
    database_sqlite3_stmt_device_by_token = database_prepare_statement(sql);
    sql = "insert into devices (token) values (?)";
    database_sqlite3_stmt_device_add = database_prepare_statement(sql);
    sql = "select id from groups where name = ?";
    database_sqlite3_stmt_group_by_name = database_prepare_statement(sql);
    sql = "insert into groups (name) values (?)";
    database_sqlite3_stmt_group_add = database_prepare_statement(sql);
    sql = "insert or ignore into subscriptions (device_id, group_id) values (?, ?)";
    database_sqlite3_stmt_subscription_add = database_prepare_statement(sql);
    sql = "delete from devices where token = ?";
    database_sqlite3_stmt_device_del = database_prepare_statement(sql);
}

int database_subscribe(char const *device, size_t device_len, char const *group, size_t group_len) {
    if (database_transaction_begin() < 0) goto transaction;
    sqlite3_int64 device_id = database_generic_select(device, device_len, database_sqlite3_stmt_device_by_token);
    if (device_id == 0) device_id = database_generic_insert(device, device_len, database_sqlite3_stmt_device_add);
    if (device_id < 0) {
        logger_propagate("Querying or inserting a device");
        goto query;
    }
    sqlite3_int64 group_id = database_generic_select(group, group_len, database_sqlite3_stmt_group_by_name);
    if (group_id == 0) group_id = database_generic_insert(group, group_len, database_sqlite3_stmt_group_add);
    if (group_id < 0) {
        logger_propagate("Querying or inserting a group");
        goto query;
    }
    if (database_insert_rel(device_id, group_id) < 0) goto query;
    if (database_transaction_commit() < 0) goto query;
    return 0;
query:
    database_transaction_rollback();
transaction:
    logger_propagate("Relating a device to a group");
    return -1;
}

int database_query_reset(void) {
    if (~database_flags & DATABASE_FLAGS_TRANSACTION && database_transaction_begin() < 0) goto transaction;
    if (sqlite3_step(database_sqlite3_stmt_group_list_clear) != SQLITE_DONE) goto query;
    sqlite3_reset(database_sqlite3_stmt_group_list_clear);
    return 0;
query:
    logger_propagate("Clearing groups: %s", sqlite3_errmsg(database_sqlite3));
    database_transaction_rollback();
transaction:
    logger_propagate("Resetting the group devices query");
    return -1;
}

int database_query_add_group(char const *group, size_t group_len) {
    if (~database_flags & DATABASE_FLAGS_TRANSACTION) {
        logger_fail("Attempted to add groups to the device group query without resetting first");
        abort();
    }
    if (sqlite3_bind_text(database_sqlite3_stmt_group_list_add, 1, group, group_len, SQLITE_TRANSIENT) != SQLITE_OK) {
        logger_propagate("Binding a value: %s", sqlite3_errmsg(database_sqlite3));
        goto transaction;
    }
    if (sqlite3_step(database_sqlite3_stmt_group_list_add) != SQLITE_DONE) {
        logger_propagate("Adding a group: %s", sqlite3_errmsg(database_sqlite3));
        goto query;
    }
    sqlite3_clear_bindings(database_sqlite3_stmt_group_list_add);
    sqlite3_reset(database_sqlite3_stmt_group_list_add);
    return 0;
query:
    sqlite3_clear_bindings(database_sqlite3_stmt_group_list_add);
    database_transaction_rollback();
transaction:
    logger_propagate("Preparing the devices group query");
    return -1;
}

int database_query_step(char const **device, size_t *device_len) {
    if (~database_flags & DATABASE_FLAGS_TRANSACTION) {
        logger_fail("Attempted to run the devices query without resetting it first");
        abort();
    }
    int status = sqlite3_step(database_sqlite3_stmt_devices_by_group_list);
    if (status == SQLITE_ROW) {
        *device = (char const *) sqlite3_column_text(database_sqlite3_stmt_devices_by_group_list, 0);
        *device_len = sqlite3_column_bytes(database_sqlite3_stmt_devices_by_group_list, 0);
        return 1;
    }
    *device = NULL;
    *device_len = 0;
    if (status != SQLITE_DONE) {
        logger_propagate("Querying for devices: %s", sqlite3_errmsg(database_sqlite3));
        goto query;
    }
    sqlite3_reset(database_sqlite3_stmt_devices_by_group_list);
    database_transaction_rollback();
    return 0;
query:
    database_transaction_rollback();
    return -1;
}

void database_query_abort(void) {
    if (~database_flags & DATABASE_FLAGS_TRANSACTION) return;
    sqlite3_reset(database_sqlite3_stmt_devices_by_group_list);
    database_transaction_rollback();
}

int database_device_del(char const *device, size_t device_len) {
    if (sqlite3_bind_text(database_sqlite3_stmt_device_del, 1, device, device_len, SQLITE_TRANSIENT) != SQLITE_OK) {
        logger_propagate("Binding a value: %s", sqlite3_errmsg(database_sqlite3));
        goto bind;
    }
    if (sqlite3_step(database_sqlite3_stmt_device_del) != SQLITE_DONE) {
        logger_propagate("Running the query: %s", sqlite3_errmsg(database_sqlite3));
        goto query;
    }
    sqlite3_clear_bindings(database_sqlite3_stmt_device_del);
    sqlite3_reset(database_sqlite3_stmt_device_del);
    return 0;
query:
    sqlite3_clear_bindings(database_sqlite3_stmt_device_del);
bind:
    logger_propagate("Deleting a device");
    return -1;
}

static int database_transaction_begin(void) {
    if (sqlite3_step(database_sqlite3_stmt_transaction_begin) != SQLITE_DONE) {
        logger_propagate("Starting a transaction: %s", sqlite3_errmsg(database_sqlite3));
        return -1;
    }
    sqlite3_reset(database_sqlite3_stmt_transaction_begin);
    database_flags |= DATABASE_FLAGS_TRANSACTION;
    return 0;
}

static void database_transaction_rollback(void) {
    sqlite3_step(database_sqlite3_stmt_transaction_rollback);
    sqlite3_reset(database_sqlite3_stmt_transaction_rollback);
    database_flags &= ~DATABASE_FLAGS_TRANSACTION;
}

static int database_transaction_commit(void) {
    if (sqlite3_step(database_sqlite3_stmt_transaction_commit) != SQLITE_DONE) {
        logger_propagate("Committing the transaction: %s", sqlite3_errmsg(database_sqlite3));
        return -1;
    }
    sqlite3_reset(database_sqlite3_stmt_transaction_commit);
    database_flags &= ~DATABASE_FLAGS_TRANSACTION;
    return 0;
}

static sqlite3_int64 database_generic_select(char const *value, size_t len, sqlite3_stmt *statement) {
    if (sqlite3_bind_text(statement, 1, value, len, SQLITE_TRANSIENT) != SQLITE_OK) {
        logger_propagate("Binding a value: %s", sqlite3_errmsg(database_sqlite3));
        return -1;
    }
    sqlite3_int64 ret = -1;
    int status = sqlite3_step(statement);
    if (status != SQLITE_ROW) goto query;
    ret = sqlite3_column_int64(statement, 0);
query:
    if (status == SQLITE_DONE || status == SQLITE_ROW) sqlite3_reset(statement);
    sqlite3_clear_bindings(statement);
    if (status == SQLITE_DONE) return 0;
    else if (status != SQLITE_ROW) logger_propagate("Running the query: %s", sqlite3_errmsg(database_sqlite3));
    return ret;
}

static sqlite3_int64 database_generic_insert(char const *value, size_t len, sqlite3_stmt *statement) {
    if (sqlite3_bind_text(statement, 1, value, len, SQLITE_TRANSIENT) != SQLITE_OK) {
        logger_propagate("Binding value: %s", sqlite3_errmsg(database_sqlite3));
        return -1;
    }
    sqlite3_int64 ret = -1;
    int status = sqlite3_step(statement);
    if (status != SQLITE_DONE) goto query;
    ret = sqlite3_last_insert_rowid(database_sqlite3);
query:
    sqlite3_clear_bindings(statement);
    if (status == SQLITE_DONE) sqlite3_reset(statement);
    else logger_propagate("Running the query: %s", sqlite3_errmsg(database_sqlite3));
    return ret;
}

static int database_insert_rel(sqlite3_int64 device_id, sqlite3_int64 group_id) {
    if (sqlite3_bind_int64(database_sqlite3_stmt_subscription_add, 1, device_id) != SQLITE_OK || sqlite3_bind_int64(database_sqlite3_stmt_subscription_add, 2, group_id) != SQLITE_OK) {
        logger_propagate("Binding a value: %s", sqlite3_errmsg(database_sqlite3));
        goto bind;
    }
    if (sqlite3_step(database_sqlite3_stmt_subscription_add) != SQLITE_DONE) {
        logger_propagate("Running the query: %s", sqlite3_errmsg(database_sqlite3));
        goto query;
    }
    sqlite3_clear_bindings(database_sqlite3_stmt_subscription_add);
    sqlite3_reset(database_sqlite3_stmt_subscription_add);
    return 0;
query:
bind:
    sqlite3_clear_bindings(database_sqlite3_stmt_subscription_add);
    logger_propagate("Inserting the relationship");
    return -1;
}

static sqlite3_stmt *database_prepare_statement(char const *sql) {
    sqlite3_stmt *statement;
    int status = sqlite3_prepare_v2(database_sqlite3, sql, -1, &statement, NULL);
    if (status != SQLITE_OK) {
        fprintf(stderr, "Unable to prepare statement %s: %s\n", sql, sqlite3_errmsg(database_sqlite3));
        exit(EXIT_FAILURE);
    }
    return statement;
}

static void database_cleanup(void) {
    if (database_sqlite3_stmt_transaction_begin) sqlite3_finalize(database_sqlite3_stmt_transaction_begin);
    if (database_sqlite3_stmt_transaction_rollback) sqlite3_finalize(database_sqlite3_stmt_transaction_rollback);
    if (database_sqlite3_stmt_transaction_commit) sqlite3_finalize(database_sqlite3_stmt_transaction_commit);
    if (database_sqlite3_stmt_group_list_clear) sqlite3_finalize(database_sqlite3_stmt_group_list_clear);
    if (database_sqlite3_stmt_group_list_add) sqlite3_finalize(database_sqlite3_stmt_group_list_add);
    if (database_sqlite3_stmt_devices_by_group_list) sqlite3_finalize(database_sqlite3_stmt_devices_by_group_list);
    if (database_sqlite3_stmt_group_by_name) sqlite3_finalize(database_sqlite3_stmt_group_by_name);
    if (database_sqlite3_stmt_group_add) sqlite3_finalize(database_sqlite3_stmt_group_add);
    if (database_sqlite3_stmt_device_by_token) sqlite3_finalize(database_sqlite3_stmt_device_by_token);
    if (database_sqlite3_stmt_device_add) sqlite3_finalize(database_sqlite3_stmt_device_add);
    if (database_sqlite3_stmt_subscription_add) sqlite3_finalize(database_sqlite3_stmt_subscription_add);
    if (database_sqlite3_stmt_device_del) sqlite3_finalize(database_sqlite3_stmt_device_del);
    if (database_sqlite3) sqlite3_close(database_sqlite3);
}
