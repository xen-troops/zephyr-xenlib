#ifndef XENLIB_XEN_SHELL_H
#define XENLIB_XEN_SHELL_H

int domu_console_start(const struct shell *shell, size_t argc, char **argv);
int domu_console_stop(const struct shell *shell, size_t argc, char **argv);
int domu_create(const struct shell *shell, size_t argc, char **argv);
int domu_destroy(const struct shell *shell, size_t argc, char **argv);
int domu_pause(const struct shell *shell, size_t argc, char **argv);
int domu_unpause(const struct shell *shell, size_t argc, char **argv);

#endif
