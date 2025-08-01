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
#include "mod_voip_patrol.hh"
#include "action.hh"
#include "check.hh"
#define THIS_FILE "voip_patrol.cc"
#include <pjsua2/account.hpp>
#include <pjsua2/call.hpp>
#include <pjsua2/endpoint.hpp>
#include <pj/ctype.h>
#include "pj_util.hpp"
#include <pjsua-lib/pjsua_internal.h>
#include <algorithm>

using namespace pj;

// RAII wrapper implementations for PJSUA Player and Recorder resources

// PjsuaPlayer implementation
PjsuaPlayer::PjsuaPlayer() : player_id_(PJSUA_INVALID_ID), valid_(false) {}

PjsuaPlayer::~PjsuaPlayer() {
	destroy();
}

pj_status_t PjsuaPlayer::create(const pj_str_t* filename, unsigned options) {
	if (valid_) {
		destroy();
	}
	
	pj_status_t status = pjsua_player_create(filename, options, &player_id_);
	if (status == PJ_SUCCESS) {
		valid_ = true;
		LOG(logINFO) << __FUNCTION__ << ": Player created successfully, ID: " << player_id_;
	} else {
		LOG(logERROR) << __FUNCTION__ << ": Failed to create player, status: " << status;
		player_id_ = PJSUA_INVALID_ID;
		valid_ = false;
	}
	return status;
}

pjsua_player_id PjsuaPlayer::get_id() const {
	return player_id_;
}

bool PjsuaPlayer::is_valid() const {
	return valid_;
}

pjsua_conf_port_id PjsuaPlayer::get_conf_port() const {
	if (!valid_) {
		return PJSUA_INVALID_ID;
	}
	return pjsua_player_get_conf_port(player_id_);
}

void PjsuaPlayer::destroy() {
	if (valid_ && player_id_ != PJSUA_INVALID_ID) {
		pj_status_t status = pjsua_player_destroy(player_id_);
		if (status != PJ_SUCCESS) {
			LOG(logERROR) << __FUNCTION__ << ": Failed to destroy player " << player_id_ << ", status: " << status;
		} else {
			LOG(logINFO) << __FUNCTION__ << ": Player " << player_id_ << " destroyed successfully";
		}
		player_id_ = PJSUA_INVALID_ID;
		valid_ = false;
	}
}

PjsuaPlayer::PjsuaPlayer(PjsuaPlayer&& other) noexcept
	: player_id_(other.player_id_), valid_(other.valid_) {
	other.player_id_ = PJSUA_INVALID_ID;
	other.valid_ = false;
}

PjsuaPlayer& PjsuaPlayer::operator=(PjsuaPlayer&& other) noexcept {
	if (this != &other) {
		destroy();
		player_id_ = other.player_id_;
		valid_ = other.valid_;
		other.player_id_ = PJSUA_INVALID_ID;
		other.valid_ = false;
	}
	return *this;
}

// PjsuaRecorder implementation
PjsuaRecorder::PjsuaRecorder() : recorder_id_(PJSUA_INVALID_ID), valid_(false) {}

PjsuaRecorder::~PjsuaRecorder() {
	destroy();
}

pj_status_t PjsuaRecorder::create(const pj_str_t* filename, unsigned enc_type, 
								  void* enc_param, pj_ssize_t max_size, 
								  unsigned options) {
	if (valid_) {
		destroy();
	}
	
	pj_status_t status = pjsua_recorder_create(filename, enc_type, enc_param, 
											   max_size, options, &recorder_id_);
	if (status == PJ_SUCCESS) {
		valid_ = true;
		LOG(logINFO) << __FUNCTION__ << ": Recorder created successfully, ID: " << recorder_id_;
	} else {
		LOG(logERROR) << __FUNCTION__ << ": Failed to create recorder, status: " << status;
		recorder_id_ = PJSUA_INVALID_ID;
		valid_ = false;
	}
	return status;
}

pjsua_recorder_id PjsuaRecorder::get_id() const {
	return recorder_id_;
}

bool PjsuaRecorder::is_valid() const {
	return valid_;
}

pjsua_conf_port_id PjsuaRecorder::get_conf_port() const {
	if (!valid_) {
		return PJSUA_INVALID_ID;
	}
	return pjsua_recorder_get_conf_port(recorder_id_);
}

void PjsuaRecorder::destroy() {
	if (valid_ && recorder_id_ != PJSUA_INVALID_ID) {
		pj_status_t status = pjsua_recorder_destroy(recorder_id_);
		if (status != PJ_SUCCESS) {
			LOG(logERROR) << __FUNCTION__ << ": Failed to destroy recorder " << recorder_id_ << ", status: " << status;
		} else {
			LOG(logINFO) << __FUNCTION__ << ": Recorder " << recorder_id_ << " destroyed successfully";
		}
		recorder_id_ = PJSUA_INVALID_ID;
		valid_ = false;
	}
}

PjsuaRecorder::PjsuaRecorder(PjsuaRecorder&& other) noexcept
	: recorder_id_(other.recorder_id_), valid_(other.valid_) {
	other.recorder_id_ = PJSUA_INVALID_ID;
	other.valid_ = false;
}

PjsuaRecorder& PjsuaRecorder::operator=(PjsuaRecorder&& other) noexcept {
	if (this != &other) {
		destroy();
		recorder_id_ = other.recorder_id_;
		valid_ = other.valid_;
		other.recorder_id_ = PJSUA_INVALID_ID;
		other.valid_ = false;
	}
	return *this;
}


void get_time_string(char * str_now, size_t buffer_size) {
	time_t t = time(0);
	struct tm * now = localtime( & t );
	snprintf(str_now, buffer_size, "%02d-%02d-%04d %02d:%02d:%02d", now->tm_mday, now->tm_mon+1, now->tm_year+1900, now->tm_hour, now->tm_min, now->tm_sec);
}

// Validate and calculate proper RTP port range
// Test cases to validate:
// - validate_and_get_port_range(4000, 0, "test") should return 14000
// - validate_and_get_port_range(4000, 3000, "test") should return 14000 (and log warning)
// - validate_and_get_port_range(4000, 8000, "test") should return 8000
// - validate_and_get_port_range(4000, 60000, "test") should return 60000 (and log warning)
int validate_and_get_port_range(int start_port, int specified_range, const std::string& context = "") {
	if (specified_range == 0 || specified_range < start_port) {
		// Use default range when specified_range is invalid or unset
		if (specified_range != 0 && specified_range < start_port && !context.empty()) {
			LOG(logWARNING) << context << " invalid port_range " << specified_range 
							<< " (less than start port " << start_port << "), using default range";
		}
		return start_port + 10000;
	} else {
		// Use specified range when valid
		int range_size = specified_range - start_port;
		if (range_size > 50000 && !context.empty()) {
			LOG(logWARNING) << context << " very large port range: " << range_size 
							<< " ports (" << start_port << "-" << specified_range << ")";
		}
		return specified_range;
	}
}

call_state_t get_call_state_from_string (string state) {
	if (state.compare("CALLING") == 0) return INV_STATE_CALLING;
	if (state.compare("INCOMING") == 0) return INV_STATE_INCOMING;
	if (state.compare("EARLY") == 0) return INV_STATE_EARLY;
	if (state.compare("CONNECTING") == 0) return INV_STATE_CONNECTING;
	if (state.compare("CONFIRMED") == 0) return INV_STATE_CONFIRMED;
	if (state.compare("DISCONNECTED") == 0) return INV_STATE_DISCONNECTED;
	return INV_STATE_NULL;
}

string get_call_state_from_id (int state) {
	if (state == INV_STATE_CALLING) return "CALLING";
	if (state == INV_STATE_INCOMING) return "INCOMING";
	if (state == INV_STATE_EARLY) return "EARLY";
	if (state == INV_STATE_CONNECTING) return "CONNECTING";
	if (state == INV_STATE_CONFIRMED) return "CONFIRMED";
	if (state == INV_STATE_DISCONNECTED) return "DISCONNECTED";
	return "UKNOWN";
}

bool stob(std::string s) {
    auto result = false;    // failure to assert is false

    std::istringstream is(s);
    // first try simple integer conversion
    is >> result;

    if (is.fail()) {
        // simple integer failed; try boolean
        is.clear();
        is >> std::boolalpha >> result;
    }

    if (is.fail()) {
        return false;
    }

    return result;
}

static pj_status_t stream_to_call(TestCall* call, pjsua_call_id call_id, const char *caller_contact ) {
	pj_status_t status = PJ_SUCCESS;
	// Create a player if none.
	if (!call->player.is_valid()) {
		LOG(logINFO) <<__FUNCTION__<< ": [stream_to_call] streaming file: " << call->test->play;
		const pj_str_t file_name = {(char*)call->test->play.c_str(), (pj_ssize_t)call->test->play.size()};
		status = call->player.create(&file_name, 0);
		if (status != PJ_SUCCESS) {
			LOG(logINFO) <<__FUNCTION__<<": [error] creating player: " << status;
			return status;
		}
	}
	LOG(logINFO) <<__FUNCTION__<< ": connecting player_id[" << call->player.get_id() << "]";

	status = pjsua_conf_connect(call->player.get_conf_port(), pjsua_call_get_conf_port(call_id));
	if (status != PJ_SUCCESS) {
		LOG(logINFO) <<__FUNCTION__<<": [error] connecting player: " << status;
	}
	return status;
}

static pj_status_t record_call(TestCall* call, pjsua_call_id call_id, const char *caller_contact, const char *recording) {
	pj_status_t status = PJ_SUCCESS;
	// Create a recorder if none.
	LOG(logINFO) <<__FUNCTION__<<": [record_call] starting recording call:" << call_id;

	if (!call->recorder.is_valid()) {
		char rec_fn[1024] = "";

		// Set recording filename
		if (strcmp(recording, "auto") == 0) {
			CallInfo ci = call->getInfo();
			snprintf(rec_fn, sizeof(rec_fn), "/srv/%s_%s_rec.wav", ci.callIdString.c_str(), caller_contact);
		} else {
			snprintf(rec_fn, sizeof(rec_fn), "%s", recording);
		}

		call->test->record_fn = string(&rec_fn[0]);
		const pj_str_t rec_file_name = pj_str(rec_fn);

		LOG(logINFO) <<__FUNCTION__<<": [record_call] recording to file:" << rec_fn;

		status = call->recorder.create(&rec_file_name, 0, NULL, -1, 0);

		if (status != PJ_SUCCESS) {
			LOG(logINFO) << __FUNCTION__ << ": [error] record_call:" << status << "\n";
			return status;
		}

		LOG(logINFO) << __FUNCTION__ << ": [recorder] created:" << call->recorder.get_id() << " to file :" << rec_fn;
	}

	int call_conf_port = pjsua_call_get_conf_port(call_id);

	LOG(logINFO) <<__FUNCTION__<<": [recorder] current call conf id:" << call_conf_port;

	if (call_conf_port == -1) {
		LOG(logINFO) << __FUNCTION__ << ": [error] cannot get call_conf_port for callid:" << call_id << "\n";

		return PJ_FALSE;
	}

	status = pjsua_conf_connect(call_conf_port, call->recorder.get_conf_port());

	if (status != PJ_SUCCESS) {
		LOG(logINFO) << __FUNCTION__ << ": [error] connect status:" << status << "\n";
	}

	return status;
}

string get_call_state_string (call_state_t state) {
	if (state == INV_STATE_CALLING) return "CALLING";
	if (state == INV_STATE_INCOMING) return "INCOMING";
	if (state == INV_STATE_EARLY) return "EARLY";
	if (state == INV_STATE_CONNECTING) return "CONNECTING";
	if (state == INV_STATE_CONFIRMED) return "CONFIRMED";
	if (state == INV_STATE_DISCONNECTED) return "DISCONNECTED";
	return "NULL";
}

/*
 * TestCall implementation
 */

/*
 * Voip_patrol version of call_param since it was not exposed and we want more control over makeCall
 */
struct vp_call_param {
	pjsua_msg_data      msg_data;
	pjsua_msg_data     *p_msg_data;
	pjsua_call_setting  opt;
	pjsua_call_setting *p_opt;
	pj_str_t            reason;
	pj_str_t           *p_reason;
	pjmedia_sdp_session *sdp;
public:
	vp_call_param(const SipTxOption &tx_option);
	vp_call_param(const SipTxOption &tx_option, const CallSetting &setting,
               const string &reason_str, pj_pool_t *pool = NULL,
               const string &sdp_str = "");
};

vp_call_param::vp_call_param(const SipTxOption &tx_option) {
	if (tx_option.isEmpty()) {
		p_msg_data = NULL;
	} else {
		tx_option.toPj(msg_data);
		p_msg_data = &msg_data;
	}
	p_opt = NULL;
	p_reason = NULL;
	sdp = NULL;
}

vp_call_param::vp_call_param(const SipTxOption &tx_option, const CallSetting &setting,
                       const string &reason_str, pj_pool_t *pool,
                       const string &sdp_str) {
	if (tx_option.isEmpty()) {
		p_msg_data = NULL;
	} else {
		tx_option.toPj(msg_data);
		p_msg_data = &msg_data;
	}

	if (setting.isEmpty()) {
		p_opt = NULL;
	} else {
		opt = setting.toPj();
		p_opt = &opt;
	}
	reason = str2Pj(reason_str);
	p_reason = (reason.slen == 0? NULL: &reason);

	sdp = NULL;
	if (sdp_str != "") {
		pj_str_t dup_pj_sdp;
		pj_str_t pj_sdp_str = {(char*)sdp_str.c_str(), (pj_ssize_t)sdp_str.size()};
		pj_status_t status;

		pj_strdup(pool, &dup_pj_sdp, &pj_sdp_str);
		status = pjmedia_sdp_parse(pool, dup_pj_sdp.ptr, dup_pj_sdp.slen, &sdp);

		if (status != PJ_SUCCESS) {
			PJ_PERROR(4,(THIS_FILE, status, "Failed to parse SDP for call param"));
		}
	}
}

void TestCall::hangup(const CallOpParam &prm) {
		if (disconnecting) {
			return;
		}
		disconnecting = true;
		LOG(logINFO) <<__FUNCTION__<<": [hangup]";
		Call::hangup(prm);
}


void TestCall::makeCall(const string &dst_uri, const CallOpParam &prm, const string &to_uri) {
	pj_str_t pj_to_uri = str2Pj(dst_uri);
	vp_call_param param(prm.txOption, prm.opt, prm.reason);

	// pjsua_call_setting
	if (test->late_start) {
		param.p_opt->flag |= PJSUA_CALL_NO_SDP_OFFER;
		LOG(logINFO) <<__FUNCTION__<< " Late-Start: flag:"<< param.p_opt->flag << " PJSUA_CALL_NO_SDP_OFFER:" <<  PJSUA_CALL_NO_SDP_OFFER;
	}
	else {
		param.p_opt->flag &= ~PJSUA_CALL_NO_SDP_OFFER;
		LOG(logINFO) <<__FUNCTION__<< " Fast-Start: flag:"<< param.p_opt->flag << " PJSUA_CALL_NO_SDP_OFFER:" <<  PJSUA_CALL_NO_SDP_OFFER;
	}

	if (!to_uri.empty()) {
		pjsua_msg_data_init(&param.msg_data);
		param.p_msg_data = &param.msg_data;
		param.p_msg_data->target_uri = str2Pj(dst_uri);
		pj_to_uri = str2Pj(to_uri);
	}

	// Adding custom headers.
	// We need to create a custom memory pool for this, as if using only pjsip_generic_string_hdr_init2
	// there are problems to add multiple headers
	pj_caching_pool cache_pool;
	pj_pool_t *header_pool;
	pj_caching_pool_init(&cache_pool, &pj_pool_factory_default_policy, 0);
	header_pool = pj_pool_create(&cache_pool.factory, "header", 1000, 1000, NULL);

	for (SipHeader sip_header : prm.txOption.headers) {
		LOG(logINFO) <<__FUNCTION__<<": Adding custom header " << sip_header.hName << " = " << sip_header.hValue;

		pj_str_t hname = str2Pj(sip_header.hName);
		pj_str_t hvalue = str2Pj(sip_header.hValue);
		pjsip_generic_string_hdr* x_header = pjsip_generic_string_hdr_create(header_pool, &hname, &hvalue);
		pj_list_push_back(&param.msg_data.hdr_list, x_header);
	}

	int id = Call::getId();
	PJSUA2_CHECK_EXPR( pjsua_call_make_call(acc->getId(), &pj_to_uri,
		param.p_opt, this, param.p_msg_data, &id) );

	pj_pool_release(header_pool);
}

TestCall::TestCall(TestAccount *p_acc, int call_id) : Call(*p_acc, call_id) {
	test = NULL;
	acc = p_acc;
	// recorder and player are automatically initialized by their constructors
	role = -1; // Caller 0 | callee 1
	disconnecting = false;
}

TestCall::~TestCall() {
	if (test) {
		Test* test_to_delete = nullptr;
		{
			test->config->checking_calls.lock();
			test->config->removeCall(this);
			test_to_delete = test;
			test = nullptr;
			test->config->checking_calls.unlock();
		}
		delete test_to_delete;
	}
}

void TestCall::setTest(Test *p_test) {
	test = p_test;
}


void TestCall::onCallRxOffer(OnCallTsxStateParam &prm) {
	PJ_UNUSED_ARG(prm);
	CallInfo ci = getInfo();
	LOG(logDEBUG) <<__FUNCTION__<<": ["<<getId()<<"]["<<ci.remoteUri<<"]["<<ci.stateText<<"]id["<<ci.callIdString<<"]";
}

void TestCall::onCallTsxState(OnCallTsxStateParam &prm) {
	PJ_UNUSED_ARG(prm);
	CallInfo ci = getInfo();

	if (prm.e.type == PJSIP_EVENT_TSX_STATE && prm.e.body.tsxState.type == PJSIP_EVENT_RX_MSG) {
		pjsip_rx_data *pjsip_rxdata = (pjsip_rx_data *) prm.e.body.tsxState.src.rdata.pjRxData;
		if (pjsip_rxdata) {
			if (pjsip_rxdata->msg_info.msg->type == PJSIP_RESPONSE_MSG) {
				int msec = 0;
				int msec_repl = pjsip_rxdata->pkt_info.timestamp.sec*1000 + pjsip_rxdata->pkt_info.timestamp.msec;
				pj_time_val s = pjsip_rxdata->pkt_info.timestamp;

				PJ_TIME_VAL_SUB(s, test->sip_latency.inviteSentTs);
				if (ci.state == PJSIP_INV_STATE_CALLING && test->sip_latency.invite100Ms == 0) {
					test->sip_latency.invite100Ms = s.sec*1000 + s.msec;
				} else if (ci.state == PJSIP_INV_STATE_EARLY && test->sip_latency.invite18xMs == 0) {
					test->sip_latency.invite18xMs = s.sec*1000 + s.msec;
					if (test->early_cancel == 1) {
						CallOpParam prm(true);
						this->hangup(prm);
						LOG(logINFO) << __FUNCTION__<< " DISCONNECTING: EARLY CANCEL RINGING:" << pjsip_rxdata->msg_info.msg->line.status.code;
					}
				} else if (ci.state == PJSIP_INV_STATE_CONFIRMED && test->sip_latency.invite200Ms == 0) {
					test->sip_latency.invite200Ms = s.sec*1000 + s.msec;
					if (test->early_cancel == 1) {
						CallOpParam prm(true);
						this->hangup(prm);
						LOG(logINFO) << __FUNCTION__ << " DISCONNECTING: EARLY CANCEL CONNECTED:" << pjsip_rxdata->msg_info.msg->line.status.code;
					}
//				} else if (ci.state == PJSIP_INV_STATE_DISCONNECTED && test->sip_latency.bye200Ms == 0) {
//					PJ_TIME_VAL_SUB(s, test->sip_latency.inviteSentTs);
//					PJ_TIME_VAL_SUB(pjsip_rxdata->pkt_info.timestamp, s);
//					msec = test->sip_latency.byeSentTs.sec*1000 + test->sip_latency.byeSentTs.msec;
				}
				LOG(logINFO) << __FUNCTION__ << " RESPONSE:" << pjsip_rxdata->msg_info.msg->line.status.code << " " << pjsip_rxdata->pkt_info.timestamp.sec << "." << pjsip_rxdata->pkt_info.timestamp.msec << " delay_ms:" << s.sec*1000 + s.msec;

			}
		}
	}

	std::string res = "call[" + std::to_string(ci.lastStatusCode) + "] reason["+ ci.lastReason +"]";
	LOG(logINFO) <<__FUNCTION__<<": ["<<getId()<<"]["<<ci.remoteUri<<"]["<<ci.stateText<<"]id["<<ci.callIdString<<"] "<<res;
	if (test) {
		test->result_cause_code = (int)ci.lastStatusCode;
		test->reason = ci.lastReason;
	}
}

/* Convenient function to convert transmission factor to MOS */
static float rfactor_to_mos(float rfactor) {
	float mos;
	if (rfactor <= 0) {
		mos = 0.0;
	} else if (rfactor > 100) {
		mos = 4.5;
	} else {
		mos = rfactor*4.5/100;
	}
	return mos;
}

void TestCall::onDtmfDigit(OnDtmfDigitParam &prm) {
	LOG(logINFO) << __FUNCTION__ << ":"<<prm.digit;
	test->dtmf_recv.append(prm.digit);
}

void TestCall::onCallMediaState(OnCallMediaStateParam &prm) {
	CallInfo ci = getInfo();

	LOG(logINFO) <<__FUNCTION__<< " id:" << ci.id;

	if (test && ci.state == PJSIP_INV_STATE_EARLY && test->record_early && test->recording.length() > 0 && !test->is_recording_running) {
		LOG(logINFO) <<__FUNCTION__<< " Start call recording in early state";

		if (record_call(this, ci.id, test->remote_user.c_str(), test->recording.c_str()) == PJ_SUCCESS) {
			test->is_recording_running = true;
		}
	}
}

void TestCall::onCallMediaUpdate(OnCallMediaStateParam &prm) {
	CallInfo ci = getInfo();
	LOG(logINFO) <<__FUNCTION__<<" id:"<<ci.id;
}

void TestCall::onStreamDestroyed(OnStreamDestroyedParam &prm) {
	CallInfo ci = getInfo();
	LOG(logINFO) <<__FUNCTION__<<" id:"<<ci.id<<" idx["<<prm.streamIdx<<"]";
	pjmedia_stream const *pj_stream = (pjmedia_stream *)&prm.stream;
	//pjmedia_stream_info *pj_stream_info;

	if (ci.state == PJSIP_INV_STATE_EARLY) {
		LOG(logINFO) << __FUNCTION__ << "State is PJSIP_INV_STATE_EARLY";
		return;
	}

	LOG(logINFO) << __FUNCTION__ << ": " << get_call_state_from_id((int)(ci.state));


	try {
		StreamInfo const &infos = getStreamInfo(prm.streamIdx);
		LOG(logINFO) << __FUNCTION__ << " codec name:"<< infos.codecName <<" clock rate:"<< infos.codecClockRate <<" RTP IP:"<< infos.remoteRtpAddress;
		StreamStat const &stats = getStreamStat(prm.streamIdx);
		RtcpStat rtcp = stats.rtcp;
		JbufState jbuf = stats.jbuf;
		RtcpStreamStat rxStat = rtcp.rxStat;
		RtcpStreamStat txStat = rtcp.txStat;

		LOG(logINFO) << __FUNCTION__ << ": RTCP Rx jitter:"<<rxStat.jitterUsec.n<<"|"<<rxStat.jitterUsec.mean/1000<<"|"<<rxStat.jitterUsec.max/1000
                     <<"Usec pkt:"<<rxStat.pkt<<" Kbytes:"<<rxStat.bytes/1024<<" loss:"<<rxStat.loss<<" discard:"<<rxStat.discard<<" discarded frames buffer:"<<jbuf.discard;
		LOG(logINFO) << __FUNCTION__ << ": RTCP Tx jitter:"<<txStat.jitterUsec.n<<"|"<<txStat.jitterUsec.mean/1000<<"|"<<txStat.jitterUsec.max/1000
                     <<"Usec pkt:"<<txStat.pkt<<" Kbytes:"<<rxStat.bytes/1024<<" loss:"<< txStat.loss<<" discard:"<<txStat.discard;

		// MOS-LQ - Listening Quality
		/* represent loss dependent effective equipment impairment factor and percentage loss probability */
		const int Bpl = 25; /* packet-loss robustness factor Bpl is defined as a codec-specific value. */
		//float Ie_eff_rx, Ppl_rx, Ppl_cut_rx, Ie_eff_tx, Ppl_tx, Ppl_cut_tx;
		float Ie_eff_rx, Ppl_rx, Ie_eff_tx, Ppl_tx;
		const int Ie = 0; /* Not used : Refer to Appendix I of [ITU-T G.113] for the currently recommended values of Ie.*/
		float Ta = 0.0; /* Absolute Delay */
		Ppl_rx = (rxStat.loss+rxStat.discard) * 100.0 / (rxStat.pkt + rxStat.loss);
		Ppl_tx = (txStat.loss+txStat.discard) * 100.0 / (txStat.pkt + txStat.loss);

		float BurstR_rx = 1.0;
		Ie_eff_rx = (Ie + (95 - Ie) * Ppl_rx / (Ppl_rx/BurstR_rx + Bpl));
		int rfactor_rx = 100 - Ie_eff_rx;
		float mos_rx = rfactor_to_mos(rfactor_rx);
		float BurstR_tx = 1.0;
		Ie_eff_tx = (Ie + (95 - Ie) * Ppl_tx / (Ppl_rx/BurstR_tx + Bpl));
		int rfactor_tx = 100 - Ie_eff_tx;
		float mos_tx = rfactor_to_mos(rfactor_tx);

		LOG(logINFO) << __FUNCTION__ <<": rtt:"<< rtcp.rttUsec.mean/1000 <<" mos_lq_tx:"<<mos_tx<<" mos_lq_rx:"<<mos_rx;
		rtt = rtcp.rttUsec.mean/1000;

		// MOS-CQ - Conversational Quality
		int mT = 100; // minimum  perceivable  delay "mT", 100ms is Applicable to all types of telephone conversations
		int sT = 1;   // delay  sensitivity "sT", 1 is Applicable to all types of telephone conversations
		float LOG2 = 0.301;
		float Id = 0; // impairment delay

		// G.107 : 7.4 Delay impairment factor, Id
		Ta = rtt/2 + jbuf.avgDelayMsec;
		if(Ta >= mT) {
			float X = (log10(Ta/mT)/LOG2);
			Id = 25.0 * (pow((1+pow(X,6.0*sT)),(1.0/(6.0*sT)))-3.0*pow((1.0+pow(X/3.0,6.0*sT)),(1.0/(6.0*sT)))+2);
		}
		int rfactor_rx_cq = rfactor_rx - Id;
		float mos_rx_cq = rfactor_to_mos(rfactor_rx_cq);
		LOG(logINFO) << __FUNCTION__ <<": Tx-mos-lq["<<mos_rx<<"] Tx-mos-cq["<<mos_rx_cq<<"] >> Ta["<<Ta<<"]jb-delay-ms["<<jbuf.avgDelayMsec<<"]";

		Ta = rtt/2 + txStat.jitterUsec.mean/500; // extrapolating dynamice jitter buffer ~jitterx2
		if(Ta >= mT) {
			float X = (log10(Ta/mT)/LOG2);
			Id = 25.0 * (pow((1+pow(X,6.0*sT)),(1.0/(6.0*sT)))-3.0*pow((1.0+pow(X/3.0,6.0*sT)),(1.0/(6.0*sT)))+2);
		}
		int rfactor_tx_cq = rfactor_tx - Id;
		float mos_tx_cq = rfactor_to_mos(rfactor_tx);
		LOG(logINFO) << __FUNCTION__ <<": Rx-mos-lq["<<mos_tx<<"] Rx-mos-cq["<<mos_tx_cq<<"] >> Ta["<<Ta<<"]RTCP_jitterX2ms["<<txStat.jitterUsec.mean/500<<"]";

		// Another interesting study to consider ...
		// https://www.naun.org/main/NAUN/mcs/2002-124.pdf

		if (test->rtp_stats_count > 0) {
			test->rtp_stats_json = test->rtp_stats_json + ',';
		}

		test->codec = std::string(infos.codecName);
		std::transform(test->codec.begin(), test->codec.end(), test->codec.begin(), ::tolower);

		test->rtp_stats_json = test->rtp_stats_json + "{\"rtt\":"+to_string(rtt)+","
			"\"remote_rtp_socket\": \""+infos.remoteRtpAddress+"\", "
			"\"codec_name\": \""+infos.codecName+"\", "
			"\"clock_rate\": \""+to_string(infos.codecClockRate)+"\", "
			"\"Tx\":{"
				"\"jitter_avg\": "+to_string(txStat.jitterUsec.mean/1000)+", "
				"\"jitter_max\": "+to_string(txStat.jitterUsec.max/1000)+", "
				"\"pkt\": "+to_string(txStat.pkt)+", "
				"\"kbytes\": "+to_string(txStat.bytes/1024)+", "
				"\"loss\": "+to_string(txStat.loss)+", "
				"\"discard\": "+to_string(txStat.discard)+", "
				"\"mos_lq\": "+to_string(mos_tx)+"} "
			", \"Rx\":{"
				"\"jitter_avg\": "+to_string(rxStat.jitterUsec.mean/1000)+", "
				"\"jitter_max\": "+to_string(rxStat.jitterUsec.max/1000)+", "
				"\"pkt\": "+to_string(rxStat.pkt)+", "
				"\"kbytes\": "+to_string(rxStat.bytes/1024)+", "
				"\"loss\": "+to_string(rxStat.loss)+", "
				"\"discard\": "+to_string(jbuf.discard)+", "
				"\"mos_lq\": "+to_string(mos_rx)+"} "
			"}";

		test->rtp_stats_count += 1;
		test->rtp_stats_ready = true;

		if (ci.state == PJSIP_INV_STATE_CONFIRMED) {
			LOG(logINFO) << __FUNCTION__ << "stateText: " << ci.stateText << " lastReason: " << ci.lastReason;
			return;
		}
		// Commented out as on onStreamDestroyed we're filling only RTP stats.
		// Problem could be on 183 - 4xx sequences, where RTP stream destroyed on 183, but real result is 4xx.
		//test->update_result();
	} catch (pj::Error& e)  {
		LOG(logERROR) << __FUNCTION__ << " error (" << e.status << "): [" << e.srcFile << "] " << e.reason << std::endl;
	}
}

void TestCall::onStreamCreated(OnStreamCreatedParam &prm) {
	CallInfo ci = getInfo();
	LOG(logINFO) <<__FUNCTION__<<" id:"<<ci.id<<" idx["<<prm.streamIdx<<"]";
}

void TestCall::onCallState(OnCallStateParam &prm) {
	PJ_UNUSED_ARG(prm);

	if (prm.e.type == PJSIP_EVENT_TX_MSG) {
		pjsip_tx_data *pjsip_txdata = (pjsip_tx_data *) prm.e.body.txMsg.tdata.pjTxData;
		if (pjsip_txdata && pjsip_txdata->msg && pjsip_txdata->msg->type == PJSIP_REQUEST_MSG) {
			LOG(logINFO) <<__FUNCTION__<<": "+ pj2Str(pjsip_txdata->msg->line.req.method.name);
		}
	} else if (prm.e.type == PJSIP_EVENT_RX_MSG) {
		pjsip_rx_data *pjsip_rxdata = (pjsip_rx_data *) prm.e.body.rxMsg.rdata.pjRxData;
		if (pjsip_rxdata && pjsip_rxdata->msg_info.msg && pjsip_rxdata->msg_info.msg->type == PJSIP_REQUEST_MSG) {
			LOG(logINFO) <<__FUNCTION__<<": "+ pj2Str(pjsip_rxdata->msg_info.msg->line.req.method.name);
			std::string message;
			message.append(pjsip_rxdata->msg_info.msg_buf, pjsip_rxdata->msg_info.len);
			if (test) {
				check_checks(test->checks, pjsip_rxdata->msg_info.msg, message);
			}
		}
	}

	CallInfo ci = getInfo();

	if (disconnecting == true && ci.state != PJSIP_INV_STATE_DISCONNECTED) {
		return;
	}

	int uri_prefix = 3; // sip:
	std::string remote_user("");
	std::string local_user("");
	std::size_t pos = ci.localUri.find("@");

	LOG(logINFO) <<__FUNCTION__<<": ["<< ci.localUri <<"]";
	if (ci.localUri[0] == '<') {
		uri_prefix++;
	}
	if (pos!=std::string::npos) {
		local_user = ci.localUri.substr(uri_prefix, pos - uri_prefix);
	}
	test->remote_uri = ci.remoteUri;
	test->local_uri = ci.localUri;
	test->remote_contact = ci.remoteContact;
	test->local_contact = ci.localContact;
	pos = ci.remoteUri.find("@");
	uri_prefix = 3;
	if (ci.remoteUri[0] != '<') {
		uri_prefix++;
	}
	if (pos!=std::string::npos) {
		remote_user = ci.remoteUri.substr(uri_prefix, pos - uri_prefix);
	}
	role = ci.role;

	if (test) {
		pjsip_tx_data *pjsip_data = (pjsip_tx_data *) prm.e.body.txMsg.tdata.pjTxData;

		if (pjsip_data && pjsip_data->tp_info.transport) {
			test->transport = pjsip_data->tp_info.transport->type_name;
			test->peer_socket = pjsip_data->tp_info.dst_name;
			test->peer_socket = test->peer_socket +":"+ std::to_string(pjsip_data->tp_info.dst_port);
		}
		if (test->state != VPT_DONE && test->wait_state && (int)test->wait_state <= (int)ci.state ) {
			test->state = VPT_RUN;
			LOG(logDEBUG) <<__FUNCTION__<<": [test-wait-return]";
		}
		LOG(logINFO) <<__FUNCTION__<<": ["<<getId()<<"]role["<<(ci.role==0?"CALLER":"CALLEE")<<"]id["<<ci.callIdString
                             <<"]["<<ci.localUri<<"]["<<ci.remoteUri<<"]["<< ci.stateText<<"|"<<ci.state<<"]";
		test->call_id = getId();
		test->sip_call_id = ci.callIdString;
	}
	if (test && (ci.state == PJSIP_INV_STATE_DISCONNECTED || ci.state == PJSIP_INV_STATE_CONFIRMED)) {
		std::string res = "call[" + std::to_string(ci.lastStatusCode) + "] reason [" + ci.lastReason + "] remote user [" + remote_user + "]";
		LOG(logINFO) << __FUNCTION__ << "[Hangup request] " << res;
		test->connect_duration = ci.connectDuration.sec;
		test->setup_duration = ci.totalDuration.sec - ci.connectDuration.sec;
		test->result_cause_code = (int)ci.lastStatusCode;
		test->reason = ci.lastReason;
		if (ci.state == PJSIP_INV_STATE_DISCONNECTED || (test->hangup_duration && ci.connectDuration.sec >= test->hangup_duration) ){
			if (test->state != VPT_DONE) {
				test->update_result();
			}
			if (ci.state == PJSIP_INV_STATE_DISCONNECTED) {
				disconnecting = true;
			}
			if (ci.state == PJSIP_INV_STATE_CONFIRMED) {
				CallOpParam prm_hangup(true);
				hangup(prm_hangup);
				LOG(logINFO) <<__FUNCTION__<<": hangup ok";
			}
		}
	}
	// Create player and recorder
	if (ci.state == PJSIP_INV_STATE_CONFIRMED) {
		if (test->play_dtmf.length() > 0) {
			dialDtmf(test->play_dtmf);
			LOG(logINFO) <<__FUNCTION__<<": [dtmf]" << test->play_dtmf;
		}

		stream_to_call(this, ci.id, test->remote_user.c_str());

		if (test->recording.length() > 0 && !test->is_recording_running) {
			if (record_call(this, ci.id, test->remote_user.c_str(), test->recording.c_str()) == PJ_SUCCESS) {
				test->is_recording_running = true;
			}
		}
	}
	if (ci.state == PJSIP_INV_STATE_DISCONNECTED) {
		std::string res = " code [" + std::to_string(ci.lastStatusCode) + "] reason ["+ ci.lastReason +"] remote user [" + remote_user + "]";
		test->rtp_stats_ready = true;
		test->update_result();

		LOG(logINFO) <<__FUNCTION__<<": [Call disconnected]:"<< res;

		// RAII wrappers will automatically clean up player and recorder resources
		// in their destructors when the TestCall object is destroyed
	}
}


/*
 * TestAccount implementation
 */

void TestAccount::setTest(Test *ptest) {
	test = ptest;
}

TestAccount::TestAccount() {
	test = NULL;
	config = NULL;
	hangup_duration = 0;
	max_duration = 0;
	ring_duration = 0;
	early_media = false;
	response_delay = 0;
	call_count = -1;
	accept_label = "default";
}

TestAccount::~TestAccount() {
	LOG(logINFO) << "[Account] is being deleted: No of calls=" << calls.size() ;
}

void TestAccount::onRegState(OnRegStateParam &prm) {
	AccountInfo ai = getInfo();
	LOG(logINFO) << (ai.regIsActive? "[Register] code:" : "[Unregister] code:") << prm.code ;
	if (!ai.regIsActive && prm.code == 200) {
		unregistering = false;
	}
	if (test) {
		if (prm.rdata.pjRxData && prm.code != 408 && prm.code != PJSIP_SC_SERVICE_UNAVAILABLE) {
			pjsip_rx_data *pjsip_data = (pjsip_rx_data *) prm.rdata.pjRxData;
			test->transport = pjsip_data->tp_info.transport->type_name;
		}
		std::string res = "registration[" + std::to_string(prm.code) + "] reason[" + prm.reason + "] expiration[" + std::to_string(prm.expiration) + "]";
		LOG(logINFO) << __FUNCTION__ << "[onRegState] " << res;
		test->result_cause_code = (int)prm.code;
		test->reason = prm.reason;
		test->update_result();
	}
}

void TestAccount::onIncomingCall(OnIncomingCallParam &iprm) {
	TestCall *call = new TestCall(this, iprm.callId);
	pjsip_rx_data *pjsip_data = (pjsip_rx_data *) iprm.rdata.pjRxData;

	std::string message;
	message.append(pjsip_data->msg_info.msg_buf, pjsip_data->msg_info.len);
	check_checks(checks, pjsip_data->msg_info.msg, message);

	CallInfo ci = call->getInfo();
	CallOpParam prm;
	AccountInfo acc_inf = getInfo();

	LOG(logINFO) <<__FUNCTION__<<":"<<" ["<< acc_inf.uri <<"]id["<<call->getId()<<"]from["<<ci.remoteUri<<"]to["<<ci.localUri<<"]id["<<ci.callIdString<<"]";
	if (!call->test) {
		LOG(logINFO)<<__FUNCTION__<<" Creating new accept test";

		if (expected_cause_code < 100 || expected_cause_code > 700) {
			expected_cause_code = 200;
		}
		string type("accept");

		LOG(logINFO)<<__FUNCTION__<<": max call duration["<< hangup_duration <<"]";

		call->test = new Test(config, type);
		call->test->checks = checks;
		call->test->hangup_duration = hangup_duration;
		call->test->max_duration = max_duration;
		call->test->ring_duration = ring_duration;
		call->test->early_media = early_media;
		call->test->response_delay = response_delay;
		call->test->re_invite_interval = re_invite_interval;
		call->test->expected_cause_code = expected_cause_code;
		call->test->cancel_behavoir = cancel_behavoir;
		call->test->fail_on_accept = fail_on_accept;
		call->test->expected_duration = expected_duration;
		call->test->expected_setup_duration = expected_setup_duration;
		call->test->expected_codec = expected_codec;

		LOG(logINFO)<<__FUNCTION__<<": local["<< ci.localUri <<"]";

		call->test->local_user = ci.localUri;
		call->test->local_uri = ci.localUri;
		call->test->remote_user = ci.remoteUri;
		call->test->remote_uri = ci.remoteUri;
		call->test->label = accept_label;
		call->test->sip_call_id = ci.callIdString;
		call->test->transport = pjsip_data->tp_info.transport->type_name;
		call->test->peer_socket = iprm.rdata.srcAddress;
		call->test->state = VPT_RUN_WAIT;
		call->test->rtp_stats = rtp_stats = true;

		LOG(logINFO) <<__FUNCTION__<<": rtp_stats:" << rtp_stats;

		call->test->late_start = late_start;
		call->test->force_contact = force_contact;
		call->test->code = (pjsip_status_code) code;
		call->test->reason = reason;
		call->test->play = play;
		call->test->recording = recording;
		call->test->record_early = record_early;

		LOG(logINFO) <<__FUNCTION__<<": play file:" << play;

		if (wait_state != INV_STATE_NULL) {
			call->test->state = VPT_RUN_WAIT;
		}

		call->test->play_dtmf = play_dtmf;
	}
	// calls.push_back(call);

	// if (call_count > 0) {
	// 	call_count -= 1;
	// 	call->test->call_count = call_count;
	// }

	config->calls.push_back(call);

	for (auto x_hdr : x_headers) {
		prm.txOption.headers.push_back(x_hdr);
	}

	if (response_delay > 0) {
		LOG(logINFO) << __FUNCTION__ << ": Not answering to the call due to response delay: " << response_delay << " ms";

		//CallOpParam prm_100;
		//prm_100.statusCode = PJSIP_SC_TRYING;
		//call->answer(prm_100);
		calls.push_back(call);
		if (call_count > 0) {
			call_count -= 1;
		}
		config->new_calls_lock.lock();
		config->new_calls.push_back(call);
		config->new_calls_lock.unlock();

		return;
	}

	// Explicitly answer with 100
	CallOpParam prm_100;

	prm_100.statusCode = PJSIP_SC_TRYING;
	call->answer(prm_100);

	LOG(logINFO) << __FUNCTION__ << " reply code:" << code << " reason:" << reason;

	if (code  >= 100 && code <= 699) {
		prm.statusCode = (pjsip_status_code) code;
	} else {
		prm.statusCode = PJSIP_SC_OK;
	}

	if (ring_duration > 0) {
			prm.statusCode = PJSIP_SC_RINGING;
			if (early_media) {
				prm.statusCode = PJSIP_SC_PROGRESS;
			}
	} else if (reason.size() > 0) {
		prm.reason = reason;
	}
	call->answer(prm);

	calls.push_back(call);

	if (call_count > 0) {
		call_count -= 1;
	}
	config->new_calls_lock.lock();
	config->new_calls.push_back(call);
	config->new_calls_lock.unlock();
}

void TestAccount::onInstantMessage(OnInstantMessageParam &prm) {

	AccountInfo ai = this->getInfo();

	LOG(logINFO) << "[Account][" << ai.id << "][" << ai.uri << "] instant message received from[" << prm.fromUri << "]message[" << prm.msgBody << "]";

	if (message_count > 0) {
		message_count -= 1;
	}

	if (testAccept) {
		testAccept->message = prm.msgBody;
		testAccept->update_result();
	}
}

void TestAccount::onInstantMessageStatus(OnInstantMessageStatusParam &prm) {

	AccountInfo ai = this->getInfo();

	LOG(logINFO) << "[Account][" << ai.id << "][" << ai.uri << "] instant message status received code:" << prm.code;

	if (test) {
		LOG(logINFO) << "[Account] instant message status received updating test code:"<< prm.code;

		test->result_cause_code = (int)prm.code;
		test->reason = prm.reason;
		test->update_result();
	} else {
		LOG(logINFO) << "[Account] instant message status received, no test found";
	}

}

/*
 *  Test implementation
 */

Test::Test(Config *config, const string& type) : config(config), type(type) {
	char now[20] = {'\0'};
	get_time_string(now, sizeof(now));
	start_time = now;
	LOG(logINFO)<<__FUNCTION__<<LOG_COLOR_INFO<<": New test created:"<<type<<LOG_COLOR_END;
}

void Test::get_mos() {
	std::string reference = "voice_ref_files/reference_8000_12s.wav";
	//std::string degraded = "voice_files/" + remote_user + "_rec.wav";
	LOG(logINFO)<<__FUNCTION__<<": [call] mos["<<mos<<"] min-mos["<<min_mos<<"] "<< reference <<" vs "<< record_fn;
}

void jsonify(std::string *str) {
	size_t index = 0;
	while (true) {
		index = str->find("\\", index);
		if (index == std::string::npos) break;
		str->replace(index, 1, "\\\\");
		index += 2;
	}
	index = 0;
	while (true) {
		index = str->find("\"", index);
		if (index == std::string::npos) break;
		str->replace(index, 1, "\\\"");
		index += 2;
	}
}

void Test::update_result() {
	char now[20] = {'\0'};
	bool success = false;
	get_time_string(now, sizeof(now));
	end_time = now;
	state = VPT_DONE;
	std::string res = "FAIL";
	std::string res_text = "No info";

	LOG(logINFO)<<__FUNCTION__;

	if (type == "accept_message") {
		if (expected_message == "" || expected_message == message) {
			res = "PASS";
			success = true;
		} else {
			LOG(logINFO) << __FUNCTION__ << "[" << expected_message << "] != [" << message << "]\n";

			res = "FAIL";
			success = false;
		}
	}

	if (min_mos > 0 && mos == 0) {
			return;
	}
	if (rtp_stats && !rtp_stats_ready && result_cause_code < 300) {
		LOG(logINFO)<<__FUNCTION__<<" push_back rtp_stats";
		if (queued) {
			return;
		}
		queued = true;
		config->tests_with_rtp_stats.push_back(this);
		return;
	}
	std::lock_guard<std::mutex> lock(config->process_result);
	if (completed) {
		LOG(logINFO) << __FUNCTION__ << "["<<this<<"]" << " already completed\n";
		return;
	}
	LOG(logINFO) <<__FUNCTION__<< "[" << this << "]" << " completing...\n";
	completed = true;

	if (fail_on_accept && type == "accept") {
		res_text = "This call should not happen";
	} else if (expected_duration && expected_duration != connect_duration) {
		res_text = "Expected duration " + std::to_string(expected_duration) + " != " + std::to_string(connect_duration) + " actual duration";
	} else if (expected_setup_duration && expected_setup_duration != setup_duration) {
		res_text = "Expected setup duration " + std::to_string(expected_setup_duration) + " != " + std::to_string(setup_duration) + " actual setup duration";
	} else if (expected_codec != "" && expected_codec != codec) {
		res_text = "Expected codec " + expected_codec + " != " + codec + " actual";
	} else if (max_duration && max_duration < connect_duration) {
		res_text = "Max call duration " + std::to_string(max_duration) + " < " + std::to_string(connect_duration) + " actual call duration";
	} else if (call_count > 0) {
		res_text = "Still " + std::to_string(call_count) + " calls left";
	} else if (result_cause_code != 487 && cancel_behavoir.compare("force") == 0) {
		res_text = "Call should be canceled";
	} else if (result_cause_code == 487 && (cancel_behavoir.compare("optional") == 0 || cancel_behavoir.compare("force") == 0)) {
		res_text = "Call canceled";
		res = "PASS";
		success = true;
	} else if (mos < min_mos) {
		res_text = "MOS is too low";
	} else if (expected_cause_code == result_cause_code) {
		res_text = "Main test passed";
		res = "PASS";
		success = true;
	}


	// JSON report
	string jsonLocalUri = local_uri;
	jsonify(&jsonLocalUri);
	string jsonLocalContact = local_contact;
	jsonify(&jsonLocalContact);
	string jsonFrom = local_user;
	if (type == "accept")
		jsonFrom = remote_user;
	string jsonTo = remote_user;
	if (type == "accept") {
		jsonTo = local_user;
	}
	jsonify(&jsonFrom);
	jsonify(&jsonTo);
	string jsonRemoteUri = remote_uri;
	jsonify(&jsonRemoteUri);
	string jsonRemoteContact = remote_contact;
	jsonify(&jsonRemoteContact);
	string jsonCallid = sip_call_id;
	jsonify(&jsonCallid);
	string jsonReason = reason;
	jsonify(&jsonReason);

	config->json_result_count += 1;

	string result_checks_json {};
	int x {0};

	for (auto check : checks) {

		LOG(logINFO) << __FUNCTION__ << " check [" << check.type << "] result[" << check.result << "]";

		if (!check.result && !fail_on_accept) {
			res = "FAIL";
			if (!check.hdr.hName.empty()) {
				res_text += "(Header " + check.hdr.hName + " failed)";
			} else if (!check.method.empty()) {
				res_text += "(Method " + check.method + " failed)";
			}
		}

		if (x > 0) {
			result_checks_json += ",";
		}
		string result = check.result ? "PASS": "FAIL";

		result_checks_json += "\"" + to_string(x) + "\":{";
		if (check.regex.empty()) {
			if (check.hdr.hValue.substr(0,6) == "regex/") {
				std::string json_val = check.hdr.hValue.substr(6);
				jsonify(&json_val);
				result_checks_json += "\"header_name\": \"" + check.hdr.hName + "\", "
						"\"regex\": \"" + json_val + "\", ";
			} else {
				result_checks_json += "\"header_name\": \"" + check.hdr.hName + "\", "
						"\"header_value\": \"" + check.hdr.hValue + "\", ";
			}
		} else {
			string json_val {check.regex};
			jsonify(&json_val);
			result_checks_json += "\"method\": \"" + check.method + "\", "
						"\"regex\": \"" + json_val + "\", ";
		}
		result_checks_json += "\"result\": \"" + result + "\"}";
		x++;
	}


	std::string result_line_json = "{\""+std::to_string(config->json_result_count)+ "/" + std::to_string(config->total_tasks_count) + "\": {"
						"\"label\": \"" + label + "\", "
						"\"start\": \"" + start_time + "\", "
						"\"end\": \"" + end_time + "\", "
						"\"action\": \"" + type + "\", "
						"\"from\": \"" + jsonFrom + "\", "
						"\"to\": \"" + jsonTo + "\", "
						"\"result\": \"" + res + "\", "
						"\"result_text\": \"" + res_text + "\", "
						"\"expected_cause_code\": " + std::to_string(expected_cause_code) + ", "
						"\"cause_code\": " + std::to_string(result_cause_code) + ", "
						"\"cancel_behavoir\": \"" + cancel_behavoir + "\", "
						"\"reason\": \"" + jsonReason + "\", "
						"\"callid\": \"" + jsonCallid + "\", "
						"\"transport\": \"" + transport + "\", "
						"\"srtp\": \"" + srtp + "\", "
						"\"peer_socket\": \"" + peer_socket + "\", "
						"\"duration\": " + std::to_string(connect_duration) + ", "
						"\"expected_duration\": " + std::to_string(expected_duration) + ", "
						"\"codec\": \"" + codec + "\", "
						"\"expected_codec\": \"" + expected_codec + "\", "
						"\"max_duration\": " + std::to_string(max_duration) + ", "
						"\"setup_duration\": " + std::to_string(setup_duration) + ", "
						"\"expected_setup_duration\": " + std::to_string(expected_setup_duration) + ", "
						"\"hangup_duration\": " + std::to_string(hangup_duration);
	if (dtmf_recv.length() > 0)
		result_line_json += ", \"dtmf_recv\": \""+dtmf_recv+"\"";


	result_line_json += ", \"call_info\":{"
						"\"local_uri\": \""+jsonLocalUri+"\", "
						"\"remote_uri\": \""+jsonRemoteUri+"\", "
						"\"local_contact\": \""+jsonLocalContact+"\", "
						"\"remote_contact\": \""+jsonRemoteContact+"\" "
						"}";

	if (type == "call") {
		result_line_json += ", \"sip_latency\" : {"
		            	"\"invite100Ms\": "+std::to_string(sip_latency.invite100Ms)+", "
			            "\"invite18xMs\": "+std::to_string(sip_latency.invite18xMs)+", "
			            "\"invite200Ms\": "+std::to_string(sip_latency.invite200Ms)+" "
				    	"}";
	}


	if (!result_checks_json.empty())
		result_line_json += ", \"check\":{" + result_checks_json + "}";

	if (rtp_stats && rtp_stats_ready)
		result_line_json += ", \"rtp_stats\":[" + rtp_stats_json + "]";
	result_line_json += "}}";

	config->result_file.write(result_line_json);
	LOG(logINFO)<<__FUNCTION__<<"["<<now<<"]" << result_line_json;
	config->result_file.flush();

	LOG(logINFO)<<" ["<<type<<"]"<<endl;

	// prepare HTML report
	std::string td_style= "style='border-color:#98B4E5;border-style:solid;padding:3px;border-width:1px;'";
	std::string td_hd_style = "style='border-color:#98B4E5;background-color: #EEF2F5;border-style:solid;padding:3px;border-width:1px;'";
	std::string td_small_style="style='padding:1px;width:50%;border-style:solid;border-spacing:0px;border-width:1px;border-color:#98B4E5;text-align:center;font-size:8pt'";
	if (config->testResults.size() == 0){
		std::string headers = "<tr>"
			"<td "+td_hd_style+">label</td>"
			"<td "+td_hd_style+">start/end</td>"
			"<td "+td_hd_style+">type</td><td "+td_hd_style+">result</td>"
			"<td "+td_hd_style+">cause code</td><td "+td_hd_style+">reason</td>"
			"<td "+td_hd_style+">duration</td>"
			"<td "+td_hd_style+">from</td><td "+td_hd_style+">to</td>\r\n";
		config->testResults.push_back(headers);
	}
	//std::string mos_color = "green";
	std::string code_color = "green";
	if (expected_cause_code != result_cause_code) {
		code_color = "red";
	}
	// if (mos < min_mos)
	// 	mos_color = "red";
	if (!success) {
		res = "<font color='red'>"+res+"</font>";
	}

	std::string html_duration_table = "<table><tr><td>expected</td><td>max</td><td>hangup</td><td>connect</td></tr><tr>"
		"<td "+td_small_style+">"+std::to_string(expected_duration)+"</td>"
		"<td "+td_small_style+">"+std::to_string(max_duration)+"</td>"
		"<td "+td_small_style+">"+std::to_string(hangup_duration)+"</td>"
		"<td "+td_small_style+">"+std::to_string(connect_duration)+"</td></tr></table>";
	type = type +"["+std::to_string(call_id)+"]transport["+transport+"]<br>peer socket["+peer_socket+"]<br>"+sip_call_id;
	std::string result = "<tr>"
		"<td "+td_style+">"+label+"</td>"
		"<td "+td_style+">"+start_time+"<br>"+end_time+"</td><td "+td_style+">"+type+"</td>"
		"<td "+td_style+">"+res+"</td>"
		"<td "+td_style+">"+std::to_string(expected_cause_code)+"|<font color="+code_color+">"+std::to_string(result_cause_code)+"</font></td>"
		"<td "+td_style+">"+reason+"</td>"
		"<td "+td_style+">"+html_duration_table+"</td>"
		"<td "+td_style+">"+local_user+"</td>"
		"<td "+td_style+">"+remote_user+"</td>"
		"</tr>\r\n";
	config->testResults.push_back(result);
}



/*
 * ResultFile implementation
 */

ResultFile::ResultFile(const std::string& name) : name(name) {
	open();
}

bool ResultFile::write(const std::string& res) {
	try {
		file << res << "\n";
	} catch (Error & err) {
		LOG(logINFO) <<__FUNCTION__<< "Exception: " << err.info() ;
		return false;
	}
	return true;
}

void ResultFile::flush() {
	file.flush();
}

bool ResultFile::open() {
	file.open(name.c_str(), std::fstream::in | std::fstream::out | std::fstream::app);
	if (file.is_open()) {
		LOG(logINFO) << "JSON result file:" << name << "\n";

		return true;
	}
	std::cerr <<__FUNCTION__<< " [error] test can not open log file :" << name ;
	return false;
}

void ResultFile::close() {
	file.close();
}


/*
 * Config implementation
 */

Config::Config(const std::string& result_fn) : result_file(result_fn), action(this) {
	tls_cfg.ca_list = "";
	tls_cfg.private_key = "";
	tls_cfg.certificate = "";
	tls_cfg.verify_server = 0;
	tls_cfg.verify_client = 0;
	json_result_count = 0;
	graceful_shutdown = false;
	rewrite_ack_transport = false;
	total_tasks_count = 0;
	memset(&this->turn_config, 0, sizeof(turn_config_t));
}

void Config::set_output_file(const std::string& file_name) {
		result_file.flush();
		result_file.close();
		result_file.name = file_name;
		result_file.open();
}

void Config::log(const std::string& message) {
	LOG(logINFO) <<"[timestamp]"<< message ;
}

Config::~Config() {
	result_file.close();
}

bool Config::removeCall(TestCall *call) {
	bool found = false;
	for (auto it = calls.begin(); it != calls.end(); ++it) {
		if (*it == call) {
			found = true;
			calls.erase(it);
			break;
		}
	}
	// Commented as it's bad idea to delete an outer variable inside a function, even with memory leaks possible
	// if (found)
	// 	delete call;
	return found;
}

void Config::createDefaultAccount() {
	AccountConfig acc_cfg;
	acc_cfg.idUri = "sip:default";
	acc_cfg.callConfig.timerUse = PJSUA_SIP_TIMER_INACTIVE;

	TestAccount *acc = createAccount(acc_cfg);
	acc->play = default_playback_file;
	LOG(logINFO) <<__FUNCTION__<<" created:"<<default_playback_file <<" TURN:"<< acc_cfg.natConfig.turnEnabled;
}

TestAccount* Config::createAccount(AccountConfig acc_cfg) {
	TestAccount *account = new TestAccount();
	accounts.push_back(account);
	account->config = this;
	acc_cfg.mediaConfig.transportConfig.port = rtp_cfg.port;

	// Validate and set RTP port range using centralized validation function
	acc_cfg.mediaConfig.transportConfig.portRange = validate_and_get_port_range(
		rtp_cfg.port, rtp_cfg.port_range, __FUNCTION__
	);

	LOG(logINFO) << __FUNCTION__ << " rtp port range: " << rtp_cfg.port << "-" << acc_cfg.mediaConfig.transportConfig.portRange;

	acc_cfg.mediaConfig.transportConfig.boundAddress = ip_cfg.bound_address;
	acc_cfg.mediaConfig.transportConfig.publicAddress = ip_cfg.public_address;
	if (ip_cfg.public_address != "")
		acc_cfg.natConfig.sipStunUse = PJSUA_STUN_USE_DISABLED;
	account->create(acc_cfg);
	AccountInfo acc_inf = account->getInfo();
	LOG(logINFO) << __FUNCTION__<< ": ["<< acc_inf.id << "]["<<acc_inf.uri<<"]";
	account->play = default_playback_file;
	return account;
}

TestAccount* Config::findAccount(std::string account_name) {
	for (auto account : accounts) {
		LOG(logINFO) << __FUNCTION__ << ": name [" << account->account_name << "]<>[" << account_name << "]";
		if (account_name == account->account_name) {
			LOG(logINFO) << __FUNCTION__ << ": found account based on name: " << account_name;

			return account;
		}
	}
	LOG(logINFO) << __FUNCTION__ << ": falling back to URI search";
	if (account_name.compare(0, 1, "+") == 0) {
		account_name.erase(0,1);
	}
	for (auto account : accounts) {
		AccountInfo acc_inf = account->getInfo();
		int proto_length = 4; // "sip:"
		if (acc_inf.uri.compare(0, 4, "sips") == 0) {
			proto_length = 5;
		}
		LOG(logINFO) << __FUNCTION__ << ": [searching account]["<< acc_inf.id << "]["<<acc_inf.uri<<"]["<<acc_inf.uri.substr(proto_length)<<"]<>["<<account_name<<"]";
		if (acc_inf.uri.compare(proto_length, account_name.length(), account_name) == 0) {
			LOG(logINFO) << __FUNCTION__ << ": found account id["<< acc_inf.id <<"] uri[" << acc_inf.uri <<"]";
			return account;
		}
	}
	return nullptr;
}

bool Config::process(const std::string& p_configFileName, const std::string& p_jsonResultFileName) {
	ezxml_t xml_actions, xml_action, xml_xhdr, xml_check, xml_param;
	configFileName = p_configFileName;
	ezxml_t xml_conf = ezxml_parse_file(configFileName.c_str());
	xml_conf_head = xml_conf; // saving the head if the linked list

	if(!xml_conf){
		LOG(logINFO) <<__FUNCTION__<< "[error] test can not load file :" << configFileName ;
		return false;
	}
replay:
	for (xml_param = ezxml_child(xml_conf, "param"); xml_param; xml_param=xml_param->next) {
		const char * n = ezxml_attr(xml_param, "name");
		const char * v = ezxml_attr(xml_param, "value");
		if (!n || !v) {
			LOG(logERROR) <<__FUNCTION__<<" invalid config param !";
			continue;
		}
		LOG(logINFO) <<__FUNCTION__<< " param ===> name["<<n<<"] value["<<v<<"]";
	}

	for (xml_actions = ezxml_child(xml_conf, "actions"); xml_actions; xml_actions=xml_actions->next) {
		LOG(logINFO) <<__FUNCTION__<< " ===> " << xml_actions->name;
		for (xml_action = ezxml_child(xml_actions, "action"); xml_action; xml_action=xml_action->next) {
			const char * val = ezxml_attr(xml_action,"type");
			if (!val) {
				LOG(logERROR) <<__FUNCTION__<<" invalid action !";
				continue;
			}

			SipHeaderVector x_hdrs = SipHeaderVector();
			for (xml_xhdr = ezxml_child(xml_action, "x-header"); xml_xhdr; xml_xhdr=xml_xhdr->next) {

				SipHeader sh = SipHeader();
				sh.hName = ezxml_attr(xml_xhdr, "name");
				sh.hValue = ezxml_attr(xml_xhdr, "value");

				if (sh.hValue.compare(0, 7, "VP_ENV_") == 0){
					if (const char* h_val = std::getenv(sh.hValue.c_str())) {
						LOG(logINFO) << __FUNCTION__ << ":" << sh.hValue << " substitution x-header:" << sh.hName << " " << h_val;

						sh.hValue = h_val;
					}
				}
				x_hdrs.push_back(sh);
			}
			vector<ActionCheck> checks;
			// TO DO: these checks sould use get/set params like we do with action params
			// <check-message>
			for (xml_check = ezxml_child(xml_action, "check-message"); xml_check; xml_check=xml_check->next) {
				ActionCheck check;
				check.type = "message";
				const char * val_inner = ezxml_attr(xml_check, "method");
				if (val_inner) {
					check.method = string(val_inner);
				} else {
					LOG(logERROR) <<__FUNCTION__<<"<check-message> missing [method] param !";
					continue;
				}
				val_inner = ezxml_attr(xml_check, "regex");
				if (val_inner) {
					check.regex = string(val_inner);
				} else {
					LOG(logERROR) <<__FUNCTION__<<"<check-message> missing [regex] param !";
					continue;
				}
				val_inner = ezxml_attr(xml_check, "code");
				if (val_inner) {
					check.code = safe_atoi(val_inner);
				}
				val_inner = ezxml_attr(xml_check, "fail_on_match");
				if (val_inner) {
					check.fail_on_match = stob(val_inner);
				}
				LOG(logINFO) << __FUNCTION__ << " check-message: method[" << check.method << "] regex[" << check.regex<<"] fail_on_match[" << check.fail_on_match << "]";

				checks.push_back(check);
			}
			// <checks-header>
			for (xml_check = ezxml_child(xml_action, "check-header"); xml_check; xml_check=xml_check->next) {
				ActionCheck check;
				check.type = "header";
				const char * val_inner = ezxml_attr(xml_check, "name");
				if (!val_inner) {
					LOG(logERROR) <<__FUNCTION__<<" missing action check header name !";
					continue;
				}
				check.hdr.hName = val_inner;
				val_inner = ezxml_attr(xml_check, "value");
				if (val_inner) {
					check.hdr.hValue = val_inner;
				} else {
					val_inner = ezxml_attr(xml_check, "regex");
					if (val_inner) {
						std::string tmp_val;
						tmp_val.assign(val_inner);
						check.hdr.hValue = "regex/" + tmp_val;
					}
				}
				val_inner = ezxml_attr(xml_check, "fail_on_match");
				if (val_inner) {
					check.fail_on_match = stob(val_inner);
				}
				LOG(logINFO) <<__FUNCTION__<< " check-header:" << check.hdr.hName << " " << check.hdr.hValue << " fail_on_match: " << check.fail_on_match;

				checks.push_back(check);
			}
			string action_type = ezxml_attr(xml_action,"type");;
			LOG(logINFO) <<__FUNCTION__<< " ===> action/" << action_type;
			if (action_type == "replay") {
				goto replay;
			}
			vector<ActionParam> params = action.get_params(action_type);
			if (params.size() == 0) {
				LOG(logERROR) <<__FUNCTION__<< ": params not found for action:" << action_type << std::endl;
				continue;
			}

			for (auto &param : params) {
				action.set_param(param, ezxml_attr(xml_action, param.name.c_str()));
			}

			if (action_type.compare("wait") == 0) {
				action.do_wait(params);
			} else if (action_type.compare("call") == 0) {
				total_tasks_count += 1;
				action.do_call(params, checks, x_hdrs);
			} else if (action_type.compare("accept") == 0) {
				total_tasks_count += 1;
				action.do_accept(params, checks, x_hdrs);
			} else if (action_type.compare("register") == 0) {
				total_tasks_count += 1;
				action.do_register(params, checks, x_hdrs);
			} else if ( action_type.compare("alert") == 0) {
				action.do_alert(params);
			} else if (action_type.compare("codec") == 0) {
				action.do_codec(params);
			} else if (action_type.compare("turn") == 0) {
				action.do_turn(params);
			} else if (action_type.compare("message") == 0) {
				total_tasks_count += 1;
				action.do_message(params, checks, x_hdrs);
			} else if (action_type.compare("accept_message") == 0) {
				total_tasks_count += 1;
				action.do_accept_message(params, checks, x_hdrs);
			}
		}
	}
	return true;
}


/*
 * Alert implementation
 */

Alert::Alert(Config * p_config){
	curl = curl_easy_init();
	config = p_config;
}
void Alert::prepare(void){
//	std::string date = "Date: Mon, 29 Nov 2010 21:54:29 +1100\r\n";
//	upload_data.payload_content.push_back(date);
	alert_server_url = config->alert_server_url;
	std::string to = "To: <"+config->alert_email_to+">\r\n";
	upload_data.payload_content.push_back(to);
	std::string from = "From: <"+config->alert_email_from+">\r\n";
	upload_data.payload_content.push_back(from);
	std::string messageId = "Message-ID: <dcd7cb36-11db-487a-9f3a-e652a9458efd@rfcpedant.example.org>\r\n";
	upload_data.payload_content.push_back(messageId);
	std::string subject = "Subject: VoIP Patrol test report\r\n";
	upload_data.payload_content.push_back(subject);
	std::string content_type = "Content-type: text/html\r\n";
	upload_data.payload_content.push_back(content_type);
	std::string bodySeparator = "\r\n";
	upload_data.payload_content.push_back(bodySeparator);

	std::string tb_style = "style='font-size:8pt;font-family:\"DejaVu Sans\",Verdana;"
                                       "border-collapse:collapse;border-spacing:0px;"
                                       "border-style:solid;border-width:1px;text-align:center;'";
	std::string html_start = "<html><table "+tb_style+">";
	upload_data.payload_content.push_back(html_start);
	for (auto & testResult : config->testResults) {
		upload_data.payload_content.push_back(testResult);
	}
	std::string html_end = "</table></html>\n\r";
	upload_data.payload_content.push_back(html_end);
}

void Alert::send(void) {
	CURLcode res = CURLE_OK;
	struct curl_slist *recipients = NULL;
	upload_data.lines_read = 0;
	LOG(logINFO) <<__FUNCTION__<< " smtp" << config->alert_server_url;
	if (config->alert_server_url.empty() || config->alert_email_to.empty() || config->alert_email_from.empty()) {
		return;
	}

	prepare();
	if(curl) {
		curl_easy_setopt(curl, CURLOPT_URL, alert_server_url.c_str());
		curl_easy_setopt(curl, CURLOPT_MAIL_FROM, alert_email_from.c_str());
		recipients = curl_slist_append(recipients, config->alert_email_to.c_str());
		curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, &Alert::payload_source);
		curl_easy_setopt(curl, CURLOPT_READDATA, &upload_data);
		curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
		curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
		res = curl_easy_perform(curl);
		if(res != CURLE_OK) {
			std::cerr << "curl_easy_perform() failed: "  << curl_easy_strerror(res) << alert_server_url <<"\n";
		}
		curl_slist_free_all(recipients);
		curl_easy_cleanup(curl);
	}
	LOG(logINFO) << "email alert sent...\n";
}

size_t Alert::payload_source(void *ptr, size_t size, size_t nmemb, void *userp) {
	upload_data_t *upload_data = (upload_data_t *)userp;
	const char *data;

	if((size == 0) || (nmemb == 0) || ((size*nmemb) < 1)) {
		return 0;
	}

	if(upload_data->lines_read >= upload_data->payload_content.size())
		return 0;
	data = upload_data->payload_content[upload_data->lines_read].c_str();
	if(data) {
		size_t len = strlen(data);
		memcpy(ptr, data, len);
		upload_data->lines_read++;
		return len;
	}

	return 0;
}

/*
*   VoipPatrolEndpoint implementation
*/

void VoipPatrolEnpoint::onSelectAccount(OnSelectAccountParam &param) {
	LOG(logDEBUG) <<__FUNCTION__<<" account_index:" << param.accountIndex << "\n" << param.rdata.wholeMsg;

	pjsip_rx_data* pjsip_data = (pjsip_rx_data *) param.rdata.pjRxData;
	pjsip_uri* request_line = pjsip_data->msg_info.msg->line.req.uri;

	if (!(PJSIP_URI_SCHEME_IS_SIP(request_line) || PJSIP_URI_SCHEME_IS_SIPS(request_line))) {
		LOG(logERROR) << __FUNCTION__ << " Request scheme is not SIP/SIPS!\n" << param.rdata.wholeMsg;

		return;
	}

	std::string to;

	// Check if we have vp_acc parameter in RURI
	char param_account_name[] = "vp_acc";
	pj_str_t param_account_pj_str = pj_str(param_account_name);
	pjsip_param* is_account = pjsip_param_find(&((pjsip_sip_uri*) request_line)->other_param, &param_account_pj_str);

	if (is_account != NULL) {
		std::string tmp_str(is_account->value.ptr, is_account->value.slen);
		to = tmp_str;

		LOG(logINFO) << __FUNCTION__ << " VOLTS account is found:" << to;
	} else {
		pjsip_to_hdr* to_hdr = (pjsip_to_hdr*) pjsip_msg_find_hdr(pjsip_data->msg_info.msg, PJSIP_H_TO, NULL);
		const pjsip_sip_uri* sip_uri = (pjsip_sip_uri*) pjsip_uri_get_uri(to_hdr->uri);
		std::string tmp_str(sip_uri->user.ptr, sip_uri->user.slen);
		to = tmp_str;

		LOG(logINFO) << __FUNCTION__ << " using To header:" << to ;
	}

	TestAccount* account = config->findAccount(to);
	if (!account) {
		account = config->findAccount("default");
	}
	if (!account) {
		return;
	}
	LOG(logINFO) << __FUNCTION__ << " account_index:" << param.accountIndex << " response_delay:" << account->response_delay << " ring_duration:" << account->ring_duration;
	// if (account->response_delay > 0) {
	// 	LOG(logINFO) << __FUNCTION__ << " account_index:" << param.accountIndex << " response_delay:" << account->response_delay ;
	// 	pj_thread_sleep(account->response_delay);
	// }
	AccountInfo acc_info = account->getInfo();
	param.accountIndex = acc_info.id;
}

void VoipPatrolEnpoint::setCodecs(string &name, int priority) {
	const CodecInfoVector2 codecs = codecEnum2();
	transform(name.begin(), name.end(), name.begin(), ::tolower);
	for (auto & c : codecs) {
		string id = c.codecId;
		transform(id.begin(), id.end(), id.begin(), ::tolower);
		std::size_t found = id.find(name);
		if (found!=std::string::npos ||  name.compare("all") == 0) {
			LOG(logINFO) <<__FUNCTION__<<" codec id:"<< c.codecId << " new priority:" << priority;
			codecSetPriority(c.codecId, priority);
		} else {
			LOG(logINFO) <<__FUNCTION__<< " codec id:" << c.codecId << " priority:" << unsigned(c.priority);
		}
	}
}

int main(int argc, char **argv){
	int ret = 0;

	pjsip_cfg_t *pjsip_config = pjsip_cfg();

	pjsip_cfg()->endpt.disable_secure_dlg_check = 1;

	VoipPatrolEnpoint ep;

	std::string conf_fn = "conf.xml";
	std::string log_fn = "";
	std::string log_test_fn = "results.json";
	int port = 5070;
	int log_level_console = 2;
	int log_level_file = 10;
	Config config(log_test_fn);
	bool tcp_only = false;
	bool udp_only = false;
	int timer_ms = 0;
	config.rtp_cfg.port = 4000;
	ep.config = &config;
	config.ep = &ep;

	std::string scenario_status_string = "";
	char now[20] = {'\0'};
	std::string current_time = "";

	// command line argument
	for (int i = 1; i < argc; ++i) {
		std::string arg = argv[i];
		if ((arg == "-h") || (arg == "--help")) {
			LOG(logINFO) <<"\n"<< argv[0] <<"                                \n"\
            " -v --version                      voip_patrol version       \n"\
            " --log-level-file <0-10>           file log level            \n"\
            " --log-level-console <0-10>        console log level         \n"\
            " -p --port <5060>                  local port                \n"\
            " -c,--conf <conf.xml>              XML scenario file         \n"\
            " -l,--log <logfilename>            voip_patrol log file name \n"\
            " -t, timer_ms <ms>                 pjsua timer_d for transaction default to 32s\n"\
            " -o,--output <result.json>         json result file name, another file suffixed with \".pjsua\" will also be created with all the logs from PJ-SIP \n"\
            " --tls-calist <path/file_name>     TLS CA list (pem format)     \n"\
            " --tls-privkey <path/file_name>    TLS private key (pem format) \n"\
            " --tls-cert <path/file_name>       TLS certificate (pem format) \n"\
            " --tls-verify-server               TLS verify server certificate \n"\
            " --tls-verify-client               TLS verify client certificate \n"\
            " --rewrite-ack-transport           WIP first use case of rewriting messages before they are sent \n"\
            " --graceful-shutdown               Wait a few seconds when shuting down\n"\
            " --tcp / --udp                     Only listen to TCP/UDP    \n"\
            " --ip-addr <IP>                    Use the specifed address as SIP and RTP addresses\n"\
            " --bound-addr <IP>                 Bind transports to this IP interface\n"\
 			" --rtp-port <1-65535>              Starting port of the range used for RTP\n"\
            " --rtp-port-end <1-65535>          End of of the range range used for RTP\n"\
            "                                                             \n";
			return 0;
		} else if ( (arg == "-v") || (arg == "--version") ) {
			LOG(logINFO) <<"version: voip_patrol "<<VERSION<<std::endl;
			return 0;
		} else if ( (arg == "-c") || (arg == "--conf") ) {
			if (i + 1 < argc) {
				conf_fn = argv[++i];
			}
		} else if ( (arg == "-t") || (arg == "--timer_ms") ) {
			if (i + 1 < argc) {
				timer_ms = safe_atoi(argv[++i]);
			}
		} else if ( (arg == "--graceful-shutdown") ) {
			config.graceful_shutdown = true;
		} else if ( (arg == "--tcp") ) {
			tcp_only = true;
		} else if ( (arg == "--udp") ) {
			udp_only = true;
		} else if ( (arg == "--rewrite-ack-transport") ) {
			config.rewrite_ack_transport = true;
		} else if ( (arg == "--log-level-file") ) {
			if (i + 1 < argc) {
				log_level_file = safe_atoi(argv[++i]);
			}
		} else if ( (arg == "--log-level-console") ) {
			if (i + 1 < argc) {
				log_level_console = safe_atoi(argv[++i]);
			}
		} else if ( (arg == "-l") || (arg == "--log")) {
			if (i + 1 < argc) {
				log_fn = argv[++i];
			}
		} else if (arg == "--ip-addr") {
			config.ip_cfg.public_address = argv[++i];
			if (config.ip_cfg.bound_address == "")
				config.ip_cfg.bound_address = "0.0.0.0";
		} else if (arg == "--bound-addr") {
			config.ip_cfg.bound_address = argv[++i];
		} else if (arg == "--rtp-port") {
			config.rtp_cfg.port = safe_atoi(argv[++i]);
		} else if (arg == "--rtp-port-end") {
			config.rtp_cfg.port_range = safe_atoi(argv[++i]);
		} else if (arg == "--tls-privkey") {
			config.tls_cfg.private_key = argv[++i];
		} else if (arg == "--tls-verify-client") {
			config.tls_cfg.verify_client = 1;
		} else if (arg == "--tls-verify-server") {
			config.tls_cfg.verify_server = 1;
		} else if (arg == "--tls-calist") {
			config.tls_cfg.ca_list = argv[++i];
		} else if (arg == "--tls-cert") {
			config.tls_cfg.certificate = argv[++i];
		} else if ( (arg == "-p") || (arg == "--port")) {
			if (i + 1 < argc) {
				port = safe_atoi(argv[++i]);
			}
		} else if ( (arg == "-o") || (arg == "--output")) {
			if (i + 1 < argc) {
				log_test_fn = argv[++i];
				config.set_output_file(log_test_fn);
			}
		}
	}

	FILELog::ReportingLevel() = (TLogLevel)log_level_console;
	if ( log_fn.length() > 0 ) {
		FILELog::ReportingLevel() = logDEBUG3;
		FILE* log_fd = fopen(log_fn.c_str(), "w");
		Output2FILE::Stream() = log_fd;
	}
	if (log_fn.empty()) log_fn = log_test_fn;
	string log_fn_pjsua = log_fn + ".pjsua";
	LOG(logINFO) << "\n* * * * * * *\n"
		"voip_patrol version: "<<VERSION<<"\n"
		"configuration: "<<conf_fn<<"\n"
		"log file (voip_patrol): "<<log_fn<<"\n"
		"log file (pjsua): "<<log_fn_pjsua<<"\n"
		"output file: "<<log_test_fn<<"\n"
		"public_address: "<<config.ip_cfg.public_address<<"\n"
		"bound_address: "<<config.ip_cfg.bound_address<<"\n"
		"* * * * * * *\n";

	if (udp_only && tcp_only) {
		udp_only = false;
		tcp_only = false;
	}

	//pjsip_cfg()->tsx.t1 = 100;
	//pjsip_cfg()->tsx.t2 = 100;
	//pjsip_cfg()->tsx.t4 = 1000;
	if (timer_ms > 0)
		pjsip_cfg()->tsx.td = timer_ms;

	LOG(logINFO) <<"pjsip_config->tsx.t1 :" << pjsip_config->tsx.t1 <<"\n";

	TransportConfig tcfg;
	try {
		ep.libCreate();
		if (config.rewrite_ack_transport) {
			/* Register stateless server module */
			pj_status_t status = -1;
			struct pjsua_data* pjsua_var = pjsua_get_var();
			status = pjsip_endpt_register_module(pjsua_var->endpt, &mod_voip_patrol);
			PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
		}
		EpConfig ep_cfg;
		ep_cfg.uaConfig.maxCalls = 1000;
		ep_cfg.logConfig.level = log_level_file;
		ep_cfg.logConfig.consoleLevel = log_level_console;
		std::string pj_log_fn =  log_fn_pjsua;
		ep_cfg.logConfig.filename = pj_log_fn.c_str();
		ep_cfg.medConfig.ecTailLen = 0; // disable echo canceller
		ep_cfg.medConfig.noVad = 1;
		// ep_cfg.uaConfig.nameserver.push_back("8.8.8.8");

		ep.libInit(ep_cfg);
		// pjsua_set_null_snd_dev() before calling pjsua_start().

		tcfg.port = port;
		tcfg.publicAddress = config.ip_cfg.public_address;
		tcfg.boundAddress = config.ip_cfg.bound_address;

		// TCP and UDP transports
		if (!tcp_only) {
			config.transport_id_udp = ep.transportCreate(PJSIP_TRANSPORT_UDP, tcfg);
		}
		if (!udp_only) {
			config.transport_id_tcp = ep.transportCreate(PJSIP_TRANSPORT_TCP, tcfg);
		}
	} catch (Error & err) {
		LOG(logINFO) <<__FUNCTION__<<": Exception: " << err.info() ;
		return 1;
	}

	if (!udp_only) {
		try {
			// TLS transport
			tcfg.port = port+1;
			// Optional, set CA/certificate/private key files.
			tcfg.tlsConfig.CaListFile = config.tls_cfg.ca_list;
			tcfg.tlsConfig.certFile = config.tls_cfg.certificate;
			tcfg.tlsConfig.privKeyFile = config.tls_cfg.private_key;
			tcfg.tlsConfig.verifyServer = config.tls_cfg.verify_server;
			tcfg.tlsConfig.verifyClient = config.tls_cfg.verify_client;
			// Optional, set ciphers. You can select a certain cipher/rearrange the order of ciphers here.
			// tcfg.tlsConfig.ciphers = ep.utilSslGetAvailableCiphers();
			config.transport_id_tls = ep.transportCreate(PJSIP_TRANSPORT_TLS, tcfg);
			LOG(logINFO) <<__FUNCTION__<<": TLS tcfg.tlsConfig.ca_list      :"<< tcfg.tlsConfig.CaListFile;
			LOG(logINFO) <<__FUNCTION__<<": TLS tcfg.tlsConfig.certFile     :"<< tcfg.tlsConfig.certFile;
			LOG(logINFO) <<__FUNCTION__<<": TLS tcfg.tlsConfig.privKeyFile  :"<< tcfg.tlsConfig.privKeyFile;
			LOG(logINFO) <<__FUNCTION__<<": TLS tcfg.tlsConfig.verifyServer :"<< tcfg.tlsConfig.verifyServer;
			LOG(logINFO) <<__FUNCTION__<<": TLS tcfg.tlsConfig.verifyClient :"<< tcfg.tlsConfig.verifyClient;
			LOG(logINFO) <<__FUNCTION__<<": TLS supported :"<< config.tls_cfg.certificate;
		} catch (Error & err) {
			config.transport_id_tls = -1;
			LOG(logINFO) <<__FUNCTION__<<": Exception: TLS not supported, see README. " << err.info() ;
		}
	}

	try {
		// load config and execute test

		get_time_string(now, sizeof(now));
		current_time = now;

		scenario_status_string = "{\"scenario\": {\"state\":\"start";
		scenario_status_string += "\", \"name\":\"" + conf_fn;
		scenario_status_string += "\", \"time\":\"" + current_time + "\"}}";

		config.result_file.write(scenario_status_string);

		LOG(logINFO) << __FUNCTION__ << scenario_status_string;

		config.result_file.flush();

		pjsua_set_null_snd_dev();
		ep.libStart();

		config.createDefaultAccount();
		config.total_tasks_count = 0;
		config.process(conf_fn, log_test_fn);

		// LOG(logINFO) <<__FUNCTION__<<": final wait complete all...";

		// vector<ActionParam> params = config.action.get_params("wait");

		// config.action.set_param_by_name(&params, "complete");
		// config.action.do_wait(params);

		LOG(logINFO) <<__FUNCTION__<<": checking alerts...";

		// send email reporting
		Alert alert(&config);
		alert.send();

		LOG(logINFO) <<__FUNCTION__<<": hangup all calls..." ;
		if (config.graceful_shutdown) { // make sure we terminate transactions, not sure why this was necessary
			pj_thread_sleep(2000);
		}

		ret = PJ_SUCCESS;
	} catch (Error &err) {
		LOG(logINFO) <<__FUNCTION__<<": Exception: " << err.info() ;
		ret = 1;
	}

	bool disconnecting = true;
	while (disconnecting) {
		disconnecting = false;
		for (auto & call : config.calls) {
			pjsua_call_info pj_ci;
			CallInfo ci;
			if (call->is_disconnecting()) { // wait for call disconnections
					if (call->test && call->test->completed) {
						config.removeCall(call);
					}
					disconnecting = true;
					continue;
			}
			pj_status_t status = pjsua_call_get_info(call->getId(), &pj_ci);

			LOG(logINFO) << __FUNCTION__ << " disconnecting >>> call[" << call->getId() << "][" << call << "] ";

			if (status != PJ_SUCCESS) {
				LOG(logINFO) << __FUNCTION__ << " can not get call info, removing call["<< call->getId() <<"]["<< call <<"] "<< config.removeCall(call);
				continue;
			}
			ci.fromPj(pj_ci);

			CallOpParam prm(true);
			if (ci.state != PJSIP_INV_STATE_DISCONNECTED) {
				disconnecting = true;
				try {
					call->hangup(prm);
				} catch (pj::Error& e)  {
					LOG(logERROR) << __FUNCTION__ << " error (" << e.status << "): [" << e.srcFile << "] " << e.reason << std::endl;
				}
			} else {
				LOG(logINFO) << __FUNCTION__ << " disconnected call["<< call->getId() <<"]["<< call <<"]";

				pj_thread_sleep(500);
			}
		}
		pj_thread_sleep(50);
	}

	try {
		ep.libDestroy();
	} catch (Error &err) {
		LOG(logINFO) <<__FUNCTION__<<": Exception: " << err.info() ;
		ret = 1;
	}

	if (ret == PJ_SUCCESS) {
		LOG(logINFO) <<__FUNCTION__<<": Success" ;
	} else {
		LOG(logINFO) <<__FUNCTION__<<": Error Found" ;
	}


	get_time_string(now, sizeof(now));
	current_time = now;

	scenario_status_string = "{\"scenario\": {\"state\":\"end\" ,\"result\":\"";

	if (config.total_tasks_count != config.json_result_count) {
		scenario_status_string += "FAIL";
	} else {
		scenario_status_string += "PASS";
	}
	scenario_status_string += "\", \"name\":\"" + conf_fn;
	scenario_status_string += "\", \"time\":\"" + current_time;
	scenario_status_string += "\", \"total tasks\":\"" + std::to_string(config.total_tasks_count);
	scenario_status_string += "\", \"completed tasks\":\"" + std::to_string(config.json_result_count) + "\"}}";

	config.result_file.write(scenario_status_string);
	LOG(logINFO)<<__FUNCTION__ << scenario_status_string;
	config.result_file.flush();

	LOG(logINFO) <<__FUNCTION__<<": Watch completed, exiting" ;
	return ret;
}
