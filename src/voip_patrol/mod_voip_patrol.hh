/*
 * Copyright (C) 2016-2024 Julien Chavanton <jchavanton@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA~
 */

#ifndef MOD_VOIP_PATROL_H
#define MOD_VOIP_PATROL_H

// #include "mod_voip_patrol.h"
#include "voip_patrol.hh"

pj_status_t vp_on_tx_msg(pjsip_tx_data *tdata);

const char *mod_name = "mod_voip_patrol";

pjsip_module mod_voip_patrol = {
	NULL, NULL,                     /* prev, next.              */
	{ (char *)mod_name, 15 },      /* Name.                    */
	-1,                             /* Id                       */
	//PJSIP_MOD_PRIORITY_APPLICATION, /* Priority                 */
	1,
	NULL,                           /* load()                   */
	NULL,                           /* start()                  */
	NULL,                           /* stop()                   */
	NULL,                           /* unload()                 */
	NULL,                           /* on_rx_request()          */
	NULL,                           /* on_rx_response()         */
	vp_on_tx_msg,                   /* on_tx_request()          */
	NULL,                           /* on_tx_response()         */
	NULL,                           /* on_tsx_state()           */
};

#endif
