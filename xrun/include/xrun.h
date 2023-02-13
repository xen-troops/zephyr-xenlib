/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2023 EPAM Systems
 */

#ifndef XRUN_H_
#define XRUN_H_

enum container_status {
	RUNNING = 0,
	PAUSED,
	DESTROYED,
};

/*
 * @brief Start runx container
 *
 * @param bundle - path to the container bundle
 * @param console -_socket sochet fd to access to
 *        the Domain console
 * @param container_id - unique container id string
 *
 * @return - 0 on success and errno on error
 */
int xrun_run(const char *bundle, int console_socket, const char *container_id);

/*
 * @brief Pause runx container
 *
 * @param container_id - unique container id string
 *
 * @return - 0 on success and errno on error
 */
int xrun_pause(const char *container_id);

/*
 * @brief Resume to runx container
 *
 * @param container_id - unique container id string
 *
 * @return - 0 on success and errno on error
 */
int xrun_resume(const char *container_id);

/*
 * @brief Kill runx container
 *
 * @param container_id - unique container id string
 *
 * @return - 0 on success and errno on error
 */
int xrun_kill(const char *container_id);

/*
 * @brief Kill runx container
 *
 * @param container_id - unique container id string
 * @param state - value to store actual container status
 *
 * @return 0 on success and errno on error
 */
int xrun_state(const char *container_id, enum container_status *state);

#endif /* XRUN_H_ */
