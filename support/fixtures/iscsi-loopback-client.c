/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Test-only glue around upstream libiscsi, never a product initiator. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>
#include <iscsi.h>
#include <scsi-lowlevel.h>
#include "lio-lun-set.h"

#define TARGET "iqn.2026-10.invalid.phantowd:lio-fixture"
#define INITIATOR "iqn.2026-10.invalid.phantowd:client"
#define FOREIGN "iqn.2026-10.invalid.phantowd:foreign"
#define PEER "iqn.2026-10.invalid.phantowd:peer"
#define PORTAL "127.0.0.1:3260"
#define USER "fixture"
#define SECRET "synthetic-chap-only-2026"
#define ROTATED "synthetic-rotated-only-2026"
#define TARGET_USER "fixture-target"
#define TARGET_SECRET "synthetic-outbound-only-2026"
#define PEER_USER "fixture-peer"
#define PEER_SECRET "synthetic-peer-only-2026"
#define BLOCK 512
#define SECOND_BLOCK 4096

static int failed(struct iscsi_context *ctx, const char *stage)
{
    /* Never print the library error, URL, configfs or credential fields. */
    fprintf(stderr, "PHANTOWD_LIO_CLIENT_ERROR stage=%s\n", stage);
    if (ctx != NULL)
        iscsi_destroy_context(ctx);
    return 1;
}

static int read_exact(struct iscsi_context *ctx, unsigned long long lba,
                      const unsigned char expected[BLOCK])
{
    struct scsi_task *task = iscsi_read16_sync(ctx, 0, lba, BLOCK, BLOCK,
                                               0, 0, 0, 0, 0);
    int valid = task != NULL && task->status == SCSI_STATUS_GOOD &&
                task->datain.size == BLOCK && task->datain.data != NULL &&
                memcmp(task->datain.data, expected, BLOCK) == 0;
    if (task != NULL)
        scsi_free_scsi_task(task);
    return valid;
}

static int refused_status(const char *error, const char *mode)
{
    const char *number;
    char *end;
    long observed, expected;
    /* Exact pinned libiscsi verification failures, not TCP/timeout failures. */
    if (error != NULL && !strcmp(mode, "mutual-target-wrong"))
        return !strcmp(error, "Authentication failed. Invalid CHAP_R response from the target");
    if (error != NULL && !strcmp(mode, "mutual-user-wrong"))
        return !strcmp(error, "Failed to log in to target. Wrong CHAP targetname received: " TARGET_USER);
    if (error == NULL ||
        strncmp(error, "Failed to log in to target. Status:", 34) != 0)
        return 0;
    number = strrchr(error, '(');
    if (number == NULL || number[1] < '0' || number[1] > '9')
        return 0;
    observed = strtol(number + 1, &end, 10);
    if (end[0] != ')' || end[1] != '\0')
        return 0;
    /* Pinned LIO: authentication failed, target forbidden, unavailable TPG. */
    expected = !strcmp(mode, "foreign") ? 0x0202 :
               !strcmp(mode, "disabled") ? 0x0301 : 0x0201;
    return observed == expected;
}

/* Fixed two-backing qualification, not a caller-selected LUN/device API. */
static int multiple_ready(struct iscsi_context *ctx, int lun)
{
    struct scsi_task *task = iscsi_testunitready_sync(ctx, lun);
    int valid;
    if (task != NULL && task->status == SCSI_STATUS_CHECK_CONDITION &&
        task->sense.key == SCSI_SENSE_UNIT_ATTENTION) {
        scsi_free_scsi_task(task);
        task = iscsi_testunitready_sync(ctx, lun);
    }
    valid = task != NULL && task->status == SCSI_STATUS_GOOD;
    if (task != NULL)
        scsi_free_scsi_task(task);
    return valid;
}

static int multiple_capacity(struct iscsi_context *ctx, int lun, int block,
                             unsigned long long last)
{
    struct scsi_task *task = iscsi_readcapacity16_sync(ctx, lun);
    struct scsi_readcapacity16 *capacity;
    int valid = 0;
    if (task != NULL && task->status == SCSI_STATUS_GOOD) {
        capacity = scsi_datain_unmarshall(task);
        valid = capacity != NULL && capacity->returned_lba == last &&
                capacity->block_length == (unsigned int)block;
    }
    if (task != NULL)
        scsi_free_scsi_task(task);
    return valid;
}

static int multiple_read(struct iscsi_context *ctx, int lun, unsigned long long lba,
                         const unsigned char *expected, int block)
{
    struct scsi_task *task = iscsi_read16_sync(ctx, lun, lba, block, block,
                                             0, 0, 0, 0, 0);
    int valid = task != NULL && task->status == SCSI_STATUS_GOOD &&
                task->datain.size == block && task->datain.data != NULL &&
                memcmp(task->datain.data, expected, (size_t)block) == 0;
    if (task != NULL)
        scsi_free_scsi_task(task);
    return valid;
}

static int multiple_write(struct iscsi_context *ctx, int lun,
                          unsigned char *data, int block, int readonly)
{
    struct scsi_task *task = iscsi_write16_sync(ctx, lun, 1, data, block, block,
                                              0, 0, 0, 0, 0);
    int valid = task != NULL && (readonly ?
        task->status == SCSI_STATUS_CHECK_CONDITION &&
        task->sense.key == SCSI_SENSE_DATA_PROTECTION &&
        task->sense.ascq == SCSI_SENSE_ASCQ_WRITE_PROTECTED :
        task->status == SCSI_STATUS_GOOD);
    if (task != NULL)
        scsi_free_scsi_task(task);
    return valid;
}

static const char *multiple_luns(struct iscsi_context *ctx, const char *mode)
{
    int peer = !strcmp(mode, "multi-peer"), second = peer ? 3 : 1;
    int checked = !strcmp(mode, "multi-primary-check"), valid;
    struct scsi_task *task;
    struct scsi_reportluns_list *list;
    unsigned char first_seed[BLOCK] = {0}, first_written[BLOCK];
    unsigned char second_seed[SECOND_BLOCK] = {0}, second_written[SECOND_BLOCK];
    unsigned char denied[SECOND_BLOCK];
    memcpy(first_seed, "PHANTOWD-LIO-SEED", sizeof("PHANTOWD-LIO-SEED") - 1);
    memcpy(second_seed, "PHANTOWD-LIO-SECOND", sizeof("PHANTOWD-LIO-SECOND") - 1);
    memset(first_written, 'B', sizeof(first_written));
    memset(second_written, checked ? 'D' : 0, sizeof(second_written));
    memset(denied, 'C', sizeof(denied));
    if (!multiple_ready(ctx, 0))
        return "multi-ready-first";
    if (!multiple_ready(ctx, second))
        return "multi-ready-second";
    task = iscsi_reportluns_sync(ctx, 0, 256);
    valid = 0;
    if (task != NULL && task->status == SCSI_STATUS_GOOD) {
        list = scsi_datain_unmarshall(task);
        valid = list != NULL && fixture_lun_set_matches(list->luns, list->num, (uint16_t)second);
    }
    if (task != NULL)
        scsi_free_scsi_task(task);
    if (!valid)
        return "multi-report-luns";
    if (!multiple_capacity(ctx, 0, BLOCK, 65535))
        return "multi-capacity-first";
    if (!multiple_capacity(ctx, second, SECOND_BLOCK, 2047))
        return "multi-capacity-second";
    if (!multiple_read(ctx, 0, 0, first_seed, BLOCK) ||
        !multiple_read(ctx, 0, 1, first_written, BLOCK))
        return "multi-data-first";
    if (!multiple_read(ctx, second, 0, second_seed, SECOND_BLOCK) ||
        !multiple_read(ctx, second, 1, second_written, SECOND_BLOCK))
        return "multi-data-second";
    /* Missing ACL mapping must be a SCSI LUN refusal, not connectivity loss. */
    task = iscsi_read16_sync(ctx, peer ? 1 : 3, 0, BLOCK, BLOCK, 0, 0, 0, 0, 0);
    valid = task != NULL && task->status == SCSI_STATUS_CHECK_CONDITION &&
            task->sense.key == SCSI_SENSE_ILLEGAL_REQUEST &&
            task->sense.ascq == SCSI_SENSE_ASCQ_LOGICAL_UNIT_NOT_SUPPORTED;
    if (task != NULL)
        scsi_free_scsi_task(task);
    if (!valid)
        return "multi-ungranted-lun";
    if (!multiple_write(ctx, 0, peer ? denied : first_written, BLOCK, peer))
        return "multi-write-first";
    if (peer)
        memset(second_written, 'D', sizeof(second_written));
    if (!multiple_write(ctx, second, peer ? second_written : denied, SECOND_BLOCK, !peer))
        return "multi-write-second";
    if (!multiple_read(ctx, 0, 0, first_seed, BLOCK) ||
        !multiple_read(ctx, 0, 1, first_written, BLOCK) ||
        !multiple_read(ctx, second, 0, second_seed, SECOND_BLOCK) ||
        !multiple_read(ctx, second, 1, second_written, SECOND_BLOCK))
        return "multi-data-isolation";
    return NULL;
}

int main(int argc, char **argv)
{
    const char *mode;
    struct iscsi_context *ctx;
    struct scsi_task *task;
    struct scsi_readcapacity16 *capacity;
    unsigned char seed[BLOCK] = {0}, written[BLOCK], denied[BLOCK];
    int refusal, login, write_ok;
    int peer, mutual, rotated, held;
    unsigned char entropy[32];
    if (argc != 2)
        return failed(NULL, "arguments");
    mode = argv[1];
    if (strcmp(mode, "rw") && strcmp(mode, "ro") && strcmp(mode, "check") &&
        strcmp(mode, "wrong") && strcmp(mode, "none") && strcmp(mode, "foreign") &&
        strcmp(mode, "hold") && strcmp(mode, "disabled") && strcmp(mode, "reenabled") &&
        strcmp(mode, "mutual") && strcmp(mode, "mutual-target-wrong") &&
        strcmp(mode, "mutual-user-wrong") && strcmp(mode, "mutual-inbound-wrong") &&
        strcmp(mode, "mutual-oneway") && strcmp(mode, "mutual-oneway-refused") && strcmp(mode, "rotated") &&
        strcmp(mode, "rotated-old") && strcmp(mode, "primary-hold") &&
        strcmp(mode, "peer-ro-hold") && strcmp(mode, "peer-cross") &&
        strcmp(mode, "multi-primary") && strcmp(mode, "multi-peer") &&
        strcmp(mode, "multi-primary-check"))
        return failed(NULL, "mode");
    /* No fixed seed or pre-initialization urandom use in authentication tests. */
    if (getrandom(entropy, sizeof(entropy), GRND_NONBLOCK) != sizeof(entropy))
        return failed(NULL, "entropy");
    refusal = !strcmp(mode, "wrong") || !strcmp(mode, "none") ||
              !strcmp(mode, "foreign") || !strcmp(mode, "disabled") ||
              !strcmp(mode, "mutual-target-wrong") || !strcmp(mode, "mutual-user-wrong") ||
              !strcmp(mode, "mutual-inbound-wrong") || !strcmp(mode, "rotated-old") ||
              !strcmp(mode, "peer-cross") || !strcmp(mode, "mutual-oneway-refused");
    peer = !strcmp(mode, "peer-ro-hold") || !strcmp(mode, "peer-cross") || !strcmp(mode, "multi-peer");
    rotated = !strcmp(mode, "rotated") || !strcmp(mode, "primary-hold") ||
              !strcmp(mode, "multi-primary") || !strcmp(mode, "multi-primary-check");
    mutual = !strncmp(mode, "mutual", 6) && strcmp(mode, "mutual-oneway") && strcmp(mode, "mutual-oneway-refused");
    mutual = mutual || rotated || !strcmp(mode, "rotated-old");
    held = !strcmp(mode, "primary-hold") || !strcmp(mode, "peer-ro-hold");
    ctx = iscsi_create_context(!strcmp(mode, "foreign") ? FOREIGN : peer ? PEER : INITIATOR);
    if (ctx == NULL)
        return failed(NULL, "context");
    iscsi_set_log_level(ctx, 0);
    iscsi_set_noautoreconnect(ctx, 1);
    iscsi_set_reconnect_max_retries(ctx, 0);
    iscsi_set_tcp_user_timeout(ctx, 5000);
    if (iscsi_set_timeout(ctx, 5) != 0 ||
        iscsi_set_targetname(ctx, TARGET) != 0 ||
        iscsi_set_session_type(ctx, ISCSI_SESSION_NORMAL) != 0)
        return failed(ctx, "setup");
    if (strcmp(mode, "none") &&
        iscsi_set_initiator_username_pwd(ctx, peer && strcmp(mode, "peer-cross") ? PEER_USER : USER,
            (!strcmp(mode, "wrong") || !strcmp(mode, "mutual-inbound-wrong")) ? "deliberately-wrong" :
            (rotated || !strcmp(mode, "peer-cross")) ? ROTATED : peer ? PEER_SECRET : SECRET) != 0)
        return failed(ctx, "auth-setup");
    if (mutual && iscsi_set_target_username_pwd(ctx,
            !strcmp(mode, "mutual-user-wrong") ? "wrong-target-user" : TARGET_USER,
            !strcmp(mode, "mutual-target-wrong") ? "deliberately-wrong" : TARGET_SECRET) != 0)
        return failed(ctx, "target-auth-setup");
    /* A network failure must not be accepted as authentication refusal. */
    if (iscsi_connect_sync(ctx, PORTAL) != 0)
        return failed(ctx, "tcp-connect");
    login = iscsi_login_sync(ctx);
    if (refusal) {
        const char *error = iscsi_get_error(ctx);
        if (login == 0 || iscsi_is_logged_in(ctx) || !refused_status(error, mode))
            return failed(ctx, "login-refusal");
        if (iscsi_destroy_context(ctx) != 0)
            return failed(NULL, "refusal-close");
        printf("PHANTOWD_LIO_CLIENT_READY case=%s\n", mode);
        return 0;
    }
    if (login != 0 || !iscsi_is_logged_in(ctx)) {
        return failed(ctx, "login");
    }
    if (!strncmp(mode, "multi-", 6)) {
        const char *stage = multiple_luns(ctx, mode);
        if (stage != NULL)
            return failed(ctx, stage);
        goto logout;
    }
    /* Consume at most one expected initial SCSI Unit Attention, not I/O errors. */
    task = iscsi_testunitready_sync(ctx, 0);
    if (task != NULL && task->status == SCSI_STATUS_CHECK_CONDITION &&
        task->sense.key == SCSI_SENSE_UNIT_ATTENTION) {
        scsi_free_scsi_task(task);
        task = iscsi_testunitready_sync(ctx, 0);
    }
    if (task == NULL || task->status != SCSI_STATUS_GOOD) {
        if (task != NULL)
            scsi_free_scsi_task(task);
        return failed(ctx, "unit-ready");
    }
    scsi_free_scsi_task(task);
    task = iscsi_readcapacity16_sync(ctx, 0);
    if (task == NULL || task->status != SCSI_STATUS_GOOD) {
        if (task != NULL)
            scsi_free_scsi_task(task);
        return failed(ctx, "capacity-status");
    }
    capacity = scsi_datain_unmarshall(task);
    if (capacity == NULL || capacity->returned_lba != 65535 ||
        capacity->block_length != BLOCK) {
        scsi_free_scsi_task(task);
        return failed(ctx, "capacity-value");
    }
    scsi_free_scsi_task(task);
    memcpy(seed, "PHANTOWD-LIO-SEED", sizeof("PHANTOWD-LIO-SEED") - 1);
    memset(written, 'B', BLOCK);
    memset(denied, 'C', BLOCK);
    if (!read_exact(ctx, 0, seed))
        return failed(ctx, "retained-seed");
    if (!strcmp(mode, "rw") || !strcmp(mode, "primary-hold")) {
        /* FILEIO uses O_DSYNC with write cache disabled; FUA is not advertised. */
        task = iscsi_write16_sync(ctx, 0, 1, written, BLOCK, BLOCK, 0, 0, 0, 0, 0);
        write_ok = task != NULL && task->status == SCSI_STATUS_GOOD;
        if (task != NULL)
            scsi_free_scsi_task(task);
        if (!write_ok)
            return failed(ctx, "write");
    } else if (!strcmp(mode, "ro") || !strcmp(mode, "peer-ro-hold")) {
        task = iscsi_write16_sync(ctx, 0, 1, denied, BLOCK, BLOCK, 0, 0, 0, 0, 0);
        write_ok = task != NULL && task->status == SCSI_STATUS_CHECK_CONDITION &&
                   task->sense.key == SCSI_SENSE_DATA_PROTECTION;
        if (task != NULL)
            scsi_free_scsi_task(task);
        if (!write_ok)
            return failed(ctx, "write-protection");
    }
    if (!read_exact(ctx, 1, written))
        return failed(ctx, "readback");
    if (held) {
        const char *ready_path = peer ? "/run/phantowd-lio/peer-ready" : "/run/phantowd-lio/primary-ready";
        const char *release_path = peer ? "/run/phantowd-lio/peer-release" : "/run/phantowd-lio/primary-release";
        FILE *ready = fopen(ready_path, "wx");
        int attempt;
        if (ready == NULL || fclose(ready) != 0)
            return failed(ctx, "peer-ready");
        for (attempt = 0; attempt < 30; attempt++) {
            if (access(release_path, F_OK) == 0)
                break;
            sleep(1);
        }
        if (attempt == 30 || !read_exact(ctx, 1, written))
            return failed(ctx, "peer-lifetime");
    }
    if (!strcmp(mode, "hold")) {
        FILE *ready;
        int attempt;
        ready = fopen("/run/phantowd-lio/session-ready", "wx");
        if (ready == NULL || fclose(ready) != 0)
            return failed(ctx, "session-ready");
        /* The guest controller revokes this already-qualified session. */
        for (attempt = 0; attempt < 30; attempt++) {
            if (access("/run/phantowd-lio/revoke", F_OK) == 0)
                break;
            sleep(1);
        }
        if (attempt == 30)
            return failed(ctx, "session-budget");
        task = iscsi_read16_sync(ctx, 0, 1, BLOCK, BLOCK, 0, 0, 0, 0, 0);
        write_ok = task != NULL && task->status == SCSI_STATUS_GOOD;
        if (task != NULL)
            scsi_free_scsi_task(task);
        if (write_ok)
            return failed(ctx, "session-not-revoked");
        if (iscsi_destroy_context(ctx) != 0)
            return failed(NULL, "revocation-close");
        puts("PHANTOWD_LIO_CLIENT_READY case=revoked");
        return 0;
    }
logout:
    if (iscsi_logout_sync(ctx) != 0 || iscsi_disconnect(ctx) != 0)
        return failed(ctx, "logout");
    if (iscsi_destroy_context(ctx) != 0)
        return failed(NULL, "close");
    printf("PHANTOWD_LIO_CLIENT_READY case=%s\n", mode);
    return 0;
}
