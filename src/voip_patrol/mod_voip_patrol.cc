/*
 * Copyright (C) 2016-2024 Julien Chavanton <jchavanton@gmail.com>, Ihor Olkhovskyi <ihor@provoip.org>
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

#include "voip_patrol.hh"
#include "check.hh"
#include "pj_util.hpp"
#include <pjsua-lib/pjsua.h>
#include <pjsip/sip_util.h>
#include <map>
#include <mutex>

#define THIS_FILE "mod_voip_patrol.cc"

// The module is always registered; each behaviour is opt-in, so registration
// alone does not change stock behaviour. The per-call REFER policy lives on
// each Test and is resolved here by SIP Call-ID via vp_config.
static bool vp_rewrite_ack = false;
static Config *vp_config = nullptr;

// Last handled REFER CSeq per Call-ID. Our hook runs before the transaction
// layer, so retransmissions would otherwise re-run checks and re-send NOTIFYs.
static std::map<std::string, int> vp_refer_seen;
static std::mutex vp_refer_seen_mutex;

void vp_set_rewrite_ack(bool enabled) {
	vp_rewrite_ack = enabled;
}

void vp_set_config(Config *cfg) {
	vp_config = cfg;
}

void vp_clear_refer_seen(const std::string &call_id) {
	if (call_id.empty()) {
		return;
	}
	std::lock_guard<std::mutex> lock(vp_refer_seen_mutex);
	vp_refer_seen.erase(call_id);
}

// Policy snapshot copied by value under config->checking_calls. Never retain
// the matched Test* beyond the lock: it can be deleted from another thread.
struct vp_refer_policy {
	bool found {false};
	bool process_transfers {true};
	int reply_code {202};
	int notify_status {200};
	bool call_ended {false}; // disconnecting: drop REFER, do not re-seed vp_refer_seen
};

// Match the REFER to the active TestCall by Call-ID, optionally run the
// method="REFER" checks, and copy the call's REFER policy out.
static vp_refer_policy vp_get_refer_policy(pjsip_rx_data *rdata, const std::string &call_id, bool run_checks) {
	vp_refer_policy pol;
	if (!vp_config) {
		return pol;
	}

	std::string message;
	if (run_checks) {
		message.append(rdata->msg_info.msg_buf, rdata->msg_info.len);
	}

	std::lock_guard<std::mutex> lock(vp_config->checking_calls);
	for (TestCall *call : vp_config->calls) {
		if (!call || !call->test) {
			continue;
		}
		if (call->test->sip_call_id != call_id) {
			continue;
		}
		// Call already tearing down: ignore late REFER (retransmit after
		// vp_clear_refer_seen) so checks/NOTIFYs are not applied twice.
		if (call->is_disconnecting()) {
			LOG(logINFO) << __FUNCTION__ << ": call_id=" << call_id
			             << " is disconnecting, ignoring REFER";
			pol.found = true;
			pol.call_ended = true;
			pol.process_transfers = false;
			pol.reply_code = 0; // drop; no reply / NOTIFY
			pol.notify_status = 0;
			return pol;
		}
		if (run_checks) {
			LOG(logINFO) << __FUNCTION__ << ": running REFER checks on call_id="
			             << call_id;
			check_checks(call->test->checks, rdata->msg_info.msg, message);
		}
		pol.found = true;
		pol.process_transfers = call->test->process_transfers;
		pol.reply_code = call->test->refer_reply_code;
		pol.notify_status = call->test->refer_notify_status;
		return pol;
	}
	return pol;
}

// RFC 4488: "Refer-Sub: false" asks for no implicit subscription (no NOTIFYs).
static bool vp_refer_sub_false(pjsip_msg *msg) {
	const pj_str_t REFER_SUB = { (char *)"Refer-Sub", 9 };
	pjsip_generic_string_hdr *hdr = (pjsip_generic_string_hdr *)
		pjsip_msg_find_hdr_by_name(msg, &REFER_SUB, NULL);
	if (!hdr) {
		return false;
	}
	return pj_stricmp2(&hdr->hvalue, "false") == 0;
}

// NOTIFY sequence for an intercepted REFER accepted with 2xx: sipfrag
// "100 Trying" (active), then the configured final status (terminated).
static void vp_send_refer_notify_sequence(pjsip_rx_data *rdata, int notify_status) {
	pjsip_cid_hdr *cid = rdata->msg_info.cid;
	pjsip_to_hdr *to_hdr = rdata->msg_info.to;
	pjsip_from_hdr *from_hdr = rdata->msg_info.from;

	if (!cid || !to_hdr || !from_hdr || to_hdr->tag.slen == 0 || from_hdr->tag.slen == 0) {
		LOG(logERROR) << __FUNCTION__
		              << ": REFER missing Call-ID/To-tag/From-tag, cannot send NOTIFY";
		return;
	}

	// REFER comes from the remote: local tag = To-tag, remote tag = From-tag.
	pjsip_dialog *dlg = pjsip_ua_find_dialog(&cid->id, &to_hdr->tag,
	                                         &from_hdr->tag, PJ_TRUE);
	if (!dlg) {
		LOG(logERROR) << __FUNCTION__ << ": no dialog for Call-ID "
		              << pj2Str(cid->id) << ", NOTIFY sequence not sent";
		return;
	}

	const int refer_cseq = rdata->msg_info.cseq ? rdata->msg_info.cseq->cseq : 0;

	const struct {
		int code;
		const char *subscription_state;
	} steps[2] = {
		{ 100,           "active;expires=60" },
		{ notify_status, "terminated;reason=noresource" },
	};

	for (const auto &step : steps) {
		static const pj_str_t NOTIFY_NAME = { (char *)"NOTIFY", 6 };
		pjsip_method notify_method;
		pjsip_method_init_np(&notify_method, (pj_str_t *)&NOTIFY_NAME);

		pjsip_tx_data *tdata = NULL;
		pj_status_t status = pjsip_dlg_create_request(dlg, &notify_method, -1, &tdata);
		if (status != PJ_SUCCESS) {
			LOG(logERROR) << __FUNCTION__ << ": pjsip_dlg_create_request failed ("
			              << status << "), NOTIFY " << step.code << " not sent";
			break;
		}

		char event_buf[64];
		snprintf(event_buf, sizeof(event_buf), "refer;id=%d", refer_cseq);
		const struct {
			const char *name;
			const char *value;
		} hdrs[2] = {
			{ "Event",              event_buf },
			{ "Subscription-State", step.subscription_state },
		};
		for (const auto &h : hdrs) {
			pj_str_t hname = pj_str((char *)h.name);
			pj_str_t hvalue = pj_str((char *)h.value);
			pjsip_generic_string_hdr *hdr =
				pjsip_generic_string_hdr_create(tdata->pool, &hname, &hvalue);
			pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)hdr);
		}

		const pj_str_t *reason = pjsip_get_status_text(step.code);
		char frag_buf[128];
		snprintf(frag_buf, sizeof(frag_buf), "SIP/2.0 %d %.*s\r\n",
		         step.code, (int)reason->slen, reason->ptr);
		pj_str_t body_type = pj_str((char *)"message");
		pj_str_t body_subtype = pj_str((char *)"sipfrag;version=2.0");
		pj_str_t body_text = pj_str(frag_buf);
		tdata->msg->body = pjsip_msg_body_create(tdata->pool, &body_type,
		                                         &body_subtype, &body_text);

		// pjsip_dlg_send_request owns tdata whatever the outcome.
		status = pjsip_dlg_send_request(dlg, tdata, -1, NULL);
		if (status != PJ_SUCCESS) {
			LOG(logERROR) << __FUNCTION__ << ": pjsip_dlg_send_request failed ("
			              << status << "), NOTIFY " << step.code << " not sent";
			break;
		}
		LOG(logINFO) << __FUNCTION__ << ": NOTIFY sipfrag " << step.code
		             << " (" << step.subscription_state << ") sent";
	}

	pjsip_dlg_dec_lock(dlg);
}

pj_bool_t vp_on_rx_request(pjsip_rx_data *rdata) {
	pjsip_msg *msg = rdata->msg_info.msg;
	const pj_str_t REFER_METHOD = { (char *)"REFER", 5 };

	// Only REFER is in scope; everything else follows the normal path.
	if (pj_stricmp(&msg->line.req.method.name, &REFER_METHOD) != 0) {
		return PJ_FALSE;
	}

	if (!rdata->msg_info.cid) {
		LOG(logWARNING) << __FUNCTION__
		                << ": REFER without Call-ID, passing to pjsua";
		return PJ_FALSE;
	}
	const std::string call_id = pj2Str(rdata->msg_info.cid->id);
	const int cseq = rdata->msg_info.cseq ? rdata->msg_info.cseq->cseq : -1;

	bool retransmission = false;
	{
		std::lock_guard<std::mutex> lock(vp_refer_seen_mutex);
		auto it = vp_refer_seen.find(call_id);
		retransmission = (it != vp_refer_seen.end() && it->second == cseq);
	}

	// Checks run in both transfer modes, before the intercept decision.
	// Retransmissions skip checks but still need the policy to re-reply.
	vp_refer_policy pol = vp_get_refer_policy(rdata, call_id, !retransmission);

	if (!pol.found) {
		// ERROR: a correlation miss on process_transfers=false silently does
		// the opposite of the configured intent (pjsua follows the transfer).
		LOG(logERROR) << __FUNCTION__ << ": no TestCall for Call-ID " << call_id
		              << "; REFER checks/policy not applied, passing to pjsua";
		return PJ_FALSE;
	}

	if (!retransmission && !pol.call_ended) {
		std::lock_guard<std::mutex> lock(vp_refer_seen_mutex);
		vp_refer_seen[call_id] = cseq;
	}

	// process_transfers=true (default): let pjsua execute the transfer.
	if (pol.process_transfers) {
		return PJ_FALSE;
	}

	// Consuming the REFER hides it from the pjsua trace; log it first.
	PJ_LOG(3, (THIS_FILE, "voip_patrol intercepting REFER (%d bytes):\n"
	                      "%.*s",
	           (int)rdata->msg_info.len,
	           (int)rdata->msg_info.len, rdata->msg_info.msg_buf));

	if (pol.reply_code <= 0) {
		LOG(logINFO) << __FUNCTION__
		             << ": REFER dropped (no reply), transfer not executed";
		return PJ_TRUE; // consume; send nothing
	}

	pjsip_endpt_respond_stateless(pjsua_get_pjsip_endpt(), rdata,
	                              (pjsip_status_code)pol.reply_code,
	                              NULL, NULL, NULL);
	LOG(logINFO) << __FUNCTION__ << ": REFER answered " << pol.reply_code
	             << ", transfer not executed";

	if (retransmission) {
		LOG(logINFO) << __FUNCTION__
		             << ": REFER retransmission, NOTIFY sequence skipped";
	} else if (!PJSIP_IS_STATUS_IN_CLASS(pol.reply_code, 200)) {
		LOG(logINFO) << __FUNCTION__ << ": non-2xx REFER reply creates no "
		                                "subscription (RFC 3515), NOTIFY skipped";
	} else if (pol.notify_status == 0) {
		LOG(logINFO) << __FUNCTION__ << ": refer_notify_status=0, NOTIFY "
		                                "sequence deliberately not sent";
	} else if (vp_refer_sub_false(msg)) {
		LOG(logINFO) << __FUNCTION__
		             << ": Refer-Sub: false (RFC 4488), NOTIFY sequence skipped";
	} else {
		vp_send_refer_notify_sequence(rdata, pol.notify_status);
	}

	return PJ_TRUE; // consume so pjsua does not follow the transfer
}

pj_status_t vp_on_tx_msg(pjsip_tx_data *tdata) {
	/* Important note:
	 *  tp_info field is only valid after outgoing messages has passed
	 *  transport layer. So don't try to access tp_info when the module
	 *  has lower priority than transport layer.
	 */

	// Legacy ACK transport-param stripping is opt-in via rewrite_ack_transport.
	if (!vp_rewrite_ack) {
		return PJ_SUCCESS;
	}


	// Currently the logic is simply to strip the transport to reproduce some broken carrier, this should evolve to be controlled using PCRE
	pjsip_sip_uri *sip_uri = (pjsip_sip_uri*)tdata->msg->line.req.uri;
	LOG(logINFO) <<__FUNCTION__<<":"<< sip_uri->host.ptr <<" " << sip_uri->transport_param.ptr << "\n" ;

	sip_uri->transport_param.ptr = NULL;
	sip_uri->transport_param.slen = 0;
	pj_str_t buff;
	buff.ptr = tdata->buf.start;
	buff.slen = tdata->buf.cur - tdata->buf.start;

	LOG(logINFO) <<__FUNCTION__<<">>>> :"<<buff.slen <<" "<< sip_uri->host.ptr <<" " << sip_uri->transport_param.ptr << "\n" ;
	char packet[PJSIP_MAX_PKT_LEN];
	packet[0] = '\0';
	char *packet_ptr = packet;

	char *m = tdata->buf.start;
	const char t[12] = ";transport=";
	if (m[0] == 'A') {
		char *ret = strstr(m, t);
		if (ret) {
			memcpy(packet_ptr, tdata->buf.start, ret - tdata->buf.start);
			packet_ptr += ret - tdata->buf.start;
			*packet_ptr = ' ';
			packet_ptr++;
			while (ret && ret[0] != 'S' && ret[1] != 'I') {
				ret[0] = ' ';
				ret++;
			}
			memcpy(packet_ptr, ret, tdata->buf.cur - ret);
			packet_ptr +=  tdata->buf.cur - ret;
			tdata->buf.cur = tdata->buf.start;
			memcpy(tdata->buf.cur, packet, packet_ptr - packet);
			tdata->buf.cur += (packet_ptr - packet);
//			LOG(logINFO) <<__FUNCTION__<<">>OUT>> :\n" << tdata->buf.start << "\n" ;
		}
	}

//    PJ_LOG(3,(THIS_FILE, ">>> TX %d bytes %s to %s %s:%d:\n"
//                         "%.*s\n"
//                         "--end msg--",
//                         (tdata->buf.cur - tdata->buf.start),
//                         pjsip_tx_data_get_info(tdata),
//                         tdata->tp_info.transport->type_name,
//                         tdata->tp_info.dst_name,
//                         tdata->tp_info.dst_port,
//                         (int)(tdata->buf.cur - tdata->buf.start),
//                         tdata->buf.start));

	/* Always return success, otherwise message will not get sent! */
	return PJ_SUCCESS;
}
