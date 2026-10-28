/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026 EPAM Systems
 *
 * Xenlib Operating System Abstraction Layer (OSAL) shell interface
 *
 */
#ifndef XENLIB_OSAL_SHELL_H
#define XENLIB_OSAL_SHELL_H

/*
 * Platform-provided types and macros required by the xenlib OSAL.
 */
#include <xenlib_osal_platform.h>


/*
 * Verify that the platform provides the required macro definitions
 */
/* shell text color macros */
#ifndef XENLIB_OSAL_SHELL_NORMAL
#error "OSAL does not provide the required shell color macro: " \
	   "XENLIB_OSAL_SHELL_NORMAL"
#endif
#ifndef XENLIB_OSAL_SHELL_INFO
#error "OSAL does not provide the required shell color macro: " \
	   "XENLIB_OSAL_SHELL_INFO"
#endif
#ifndef XENLIB_OSAL_SHELL_OPTION
#error "OSAL does not provide the required shell color macro: " \
	   "XENLIB_OSAL_SHELL_OPTION"
#endif
#ifndef XENLIB_OSAL_SHELL_WARNING
#error "OSAL does not provide the required shell color macro: " \
	   "XENLIB_OSAL_SHELL_WARNING"
#endif
#ifndef XENLIB_OSAL_SHELL_ERROR
#error "OSAL does not provide the required shell color macro: " \
	   "XENLIB_OSAL_SHELL_ERROR"
#endif
/* shell output macro functions */
#ifndef xenlib_osal_shell_info
#error "OSAL does not provide the required shell output interface: " \
	   "xenlib_osal_shell_info"
#endif
#ifndef xenlib_osal_shell_warn
#error "OSAL does not provide the required shell output interface: " \
	   "xenlib_osal_shell_warn"
#endif
#ifndef xenlib_osal_shell_error
#error "OSAL does not provide the required shell output interface: " \
	   "xenlib_osal_shell_error"
#endif
#ifndef xenlib_osal_shell_print
#error "OSAL does not provide the required shell output interface: " \
	   "xenlib_osal_shell_print"
#endif
#ifndef xenlib_osal_shell_fprintf
#error "OSAL does not provide the required shell output interface: " \
	   "xenlib_osal_shell_fprintf"
#endif

/* shell commands and arguments macros */
#ifndef XENLIB_OSAL_SHELL_STATIC_SUBCMD_SET_CREATE
#error "OSAL does not provide the required shell command interface: " \
	   "XENLIB_OSAL_SHELL_STATIC_SUBCMD_SET_CREATE"
#endif
#ifndef XENLIB_OSAL_SHELL_CMD_ARG
#error "OSAL does not provide the required shell command interface: " \
	   "XENLIB_OSAL_SHELL_CMD_ARG"
#endif
#ifndef XENLIB_OSAL_SHELL_CMD_ARG_REGISTER
#error "OSAL does not provide the required shell command interface: " \
	   "XENLIB_OSAL_SHELL_CMD_ARG_REGISTER"
#endif

/**
 * @brief Set bypass callback that will be called whenever data is received.
 * Shell is bypassed and data is passed directly to the callback.
 *
 * @param shell shell instance
 * @param bypass bypass callback or NULL to disable bypass
 * @param user_data bypass callback user data (NULL if no callback data)
 */
extern void xenlib_osal_shell_set_bypass(const xenlib_osal_shell_t *shell,
										 xenlib_osal_shell_bypass_cb_t bypass,
										 void *user_data);

#endif /* XENLIB_OSAL_SHELL_H */
