#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "flecs.h"

static bool seen_internal_error = false;

static void afl_log(
    int32_t level,
    const char *file,
    int32_t line,
    const char *msg)
{
    (void)level;
    (void)file;
    (void)line;

    if (!msg) {
        return;
    }

    if (strstr(msg, "ECS_INTERNAL_ERROR")) {
        seen_internal_error = true;
        fputs(msg, stderr);
        if (msg[0] && msg[strlen(msg) - 1] != '\n') {
            fputc('\n', stderr);
        }
    }
}

static void afl_abort(void)
{
    /* Keep abort behavior only for ECS_INTERNAL_ERROR asserts. */
    if (seen_internal_error) {
        fflush(stderr);
        abort();
    }

    /* Ignore expected aborts from invalid script input. */
    _Exit(0);
}

static int read_input(const char *path, char **out, size_t *out_len)
{
    FILE *fp = fopen(path, "rb");
    char *buf = NULL;
    size_t len = 0;

    if (!fp) {
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }

    long end = ftell(fp);
    if (end < 0) {
        fclose(fp);
        return -1;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    len = (size_t)end;
    buf = malloc(len + 1);
    if (!buf) {
        fclose(fp);
        return -1;
    }

    if (len && fread(buf, 1, len, fp) != len) {
        free(buf);
        fclose(fp);
        return -1;
    }

    fclose(fp);
    buf[len] = '\0';
    *out = buf;
    *out_len = len;
    return 0;
}

static void fuzz_script_run(const char *script)
{
    ecs_world_t *world = ecs_init();
    if (!world) {
        return;
    }

#ifdef FLECS_SCRIPT_MATH
    ECS_IMPORT(world, FlecsScriptMath);
#endif

    /* Hide regular parser errors, keep fatal logs only. */
    ecs_log_set_level(-4);
    seen_internal_error = false;

    ecs_script_run(world, "afl_input", script, NULL);
    ecs_fini(world);
}

static void fuzz_script_init(const char *script) {
    ecs_world_t *world = ecs_init();
    if (!world) {
        return;
    }

#ifdef FLECS_SCRIPT_MATH
    ECS_IMPORT(world, FlecsScriptMath);
#endif

    /* Hide regular parser errors, keep fatal logs only. */
    ecs_log_set_level(-4);
    seen_internal_error = false;

    ecs_script(world, {
        .code = script
    });

    ecs_fini(world);
}

static void fuzz_script_update(const char *script) {
    ecs_world_t *world = ecs_init();
    if (!world) {
        return;
    }

#ifdef FLECS_SCRIPT_MATH
    ECS_IMPORT(world, FlecsScriptMath);
#endif

    /* Hide regular parser errors, keep fatal logs only. */
    ecs_log_set_level(-4);
    seen_internal_error = false;

    ecs_entity_t s = ecs_script(world, {
        .code = script
    });

    ecs_script_update(world, s, 0, script);
    ecs_script_update(world, s, 0, script);
    ecs_script_update(world, s, 0, script);

    ecs_fini(world);
}

int main(int argc, char *argv[])
{
    char *input = NULL;
    size_t input_len = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    ecs_os_set_api_defaults();
    ecs_os_api_t os_api = ecs_os_get_api();
    os_api.log_ = afl_log;
    os_api.abort_ = afl_abort;
    ecs_os_set_api(&os_api);

    if (read_input(argv[1], &input, &input_len) != 0) {
        return 0;
    }

    if (input_len > 0) {
        fuzz_script_run(input);
        fuzz_script_update(input);
    }

    free(input);
    return 0;
}
