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
#include "action.hh"
#include "util.hh"
#include "string.h"
#include <pjsua2/presence.hpp>
#include <stdexcept>
#include <cctype>

void filter_accountname(std::string *str) {
	size_t index = 0;
	while (true) {
		index = str->find("@", index);
		if (index == std::string::npos) break;
		str->replace(index, 1, "_");
		index += 1;
	}
	index = 0;
	while (true) {
		index = str->find(";", index);
		if (index == std::string::npos) break;
		str->replace(index, 1, "-");
		index += 1;
	}
}

// Safe string-to-integer conversion with input validation
int safe_atoi(const char* str, int default_value) {
	if (!str || *str == '\0') {
		LOG(logERROR) << "safe_atoi: null or empty string provided, using default value: " << default_value;
		return default_value;
	}

	// Check if string contains only digits (and optional leading +/-)
	const char* p = str;
	if (*p == '+' || *p == '-') p++;
	if (*p == '\0') {
		LOG(logERROR) << "safe_atoi: invalid string '" << str << "', using default value: " << default_value;
		return default_value;
	}

	while (*p) {
		if (!std::isdigit(*p)) {
			LOG(logERROR) << "safe_atoi: invalid character in string '" << str << "', using default value: " << default_value;
			return default_value;
		}
		p++;
	}

	try {
		long result = std::strtol(str, nullptr, 10);
		if (result > INT_MAX || result < INT_MIN) {
			LOG(logERROR) << "safe_atoi: value '" << str << "' out of int range, using default value: " << default_value;
			return default_value;
		}
		return static_cast<int>(result);
	} catch (const std::exception& e) {
		LOG(logERROR) << "safe_atoi: conversion failed for '" << str << "', using default value: " << default_value;
		return default_value;
	}
}

// Safe string prefix comparison with bounds checking
bool safe_string_starts_with(const std::string& str, const std::string& prefix) {
	if (str.length() < prefix.length()) {
		return false;
	}
	return str.substr(0, prefix.length()) == prefix;
}

// Input sanitization for string parameters - remove control characters
std::string sanitize_string_param(const std::string& input, size_t max_length) {
	std::string result;
	result.reserve(std::min(input.length(), max_length));

	for (size_t i = 0; i < input.length() && result.length() < max_length; ++i) {
		char c = input[i];
		// Allow printable ASCII characters, space, and common extended characters
		if ((c >= 32 && c <= 126) || c == '\t') {
			result += c;
		}
		// Skip control characters and other potentially dangerous characters
	}

	return result;
}

// Safe string-to-float conversion with input validation
float safe_atof(const char* str, float default_value) {
	if (!str || *str == '\0') {
		LOG(logERROR) << "safe_atof: null or empty string provided, using default value: " << default_value;
		return default_value;
	}

	// Basic validation for float format
	const char* p = str;
	if (*p == '+' || *p == '-') p++;
	bool has_digit = false;
	bool has_dot = false;

	while (*p) {
		if (std::isdigit(*p)) {
			has_digit = true;
		} else if (*p == '.' && !has_dot) {
			has_dot = true;
		} else {
			LOG(logERROR) << "safe_atof: invalid character in string '" << str << "', using default value: " << default_value;
			return default_value;
		}
		p++;
	}

	if (!has_digit) {
		LOG(logERROR) << "safe_atof: no digits found in string '" << str << "', using default value: " << default_value;
		return default_value;
	}

	try {
		char* endptr;
		float result = std::strtof(str, &endptr);
		if (*endptr != '\0') {
			LOG(logERROR) << "safe_atof: invalid characters after number in '" << str << "', using default value: " << default_value;
			return default_value;
		}
		return result;
	} catch (const std::exception& e) {
		LOG(logERROR) << "safe_atof: conversion failed for '" << str << "', using default value: " << default_value;
		return default_value;
	}
}

namespace {

	string normalize_transport_param(const string &transport) {
		if (transport == "udp6") return "udp";
		if (transport == "tcp6") return "tcp";
		if (transport == "tls6") return "tls";
		if (transport == "sips6") return "sips";
		return transport;
	}

	bool uri_has_ipv6_host(string uri) {
		auto lt = uri.find('<');
		auto gt = uri.find('>');
		if (lt != string::npos && gt != string::npos && gt > lt) {
			uri = uri.substr(lt + 1, gt - lt - 1);
		}

		if (uri.compare(0, 5, "sips:") == 0)
			uri = uri.substr(5);
		else if (uri.compare(0, 4, "sip:") == 0)
			uri = uri.substr(4);

		auto at_pos = uri.find('@');
		if (at_pos != string::npos)
			uri = uri.substr(at_pos + 1);

		auto param_pos = uri.find(';');
		if (param_pos != string::npos)
			uri = uri.substr(0, param_pos);

		auto query_pos = uri.find('?');
		if (query_pos != string::npos)
			uri = uri.substr(0, query_pos);

		if (!uri.empty() && uri.front() == '[') {
			auto end = uri.find(']');
			if (end != string::npos) {
				auto inside = uri.substr(1, end - 1);
				return inside.find(':') != string::npos;
			}
		}

		return std::count(uri.begin(), uri.end(), ':') >= 2;
	}

	TransportId select_transport_id(const Config *config, const string &transport, const string &target_uri) {
		string transport_lc = transport;
		vp::tolower(transport_lc);
		bool target_is_v6 = uri_has_ipv6_host(target_uri);

		if (transport_lc == "udp6") return config->transport_id_udp6;
		if (transport_lc == "tcp6") return config->transport_id_tcp6;
		if (transport_lc == "tls6" || transport_lc == "sips6") return config->transport_id_tls6;

		if (transport_lc == "udp") return target_is_v6 ? config->transport_id_udp6 : config->transport_id_udp;
		if (transport_lc == "tcp") return target_is_v6 ? config->transport_id_tcp6 : config->transport_id_tcp;
		if (transport_lc == "tls" || transport_lc == "sips")
			return target_is_v6 ? config->transport_id_tls6 : config->transport_id_tls;

		return -1;
	}

	bool is_ipv6_transport(const string &transport) {
      	string transport_lc = transport;
      	vp::tolower(transport_lc);
      	return transport_lc == "udp6" || transport_lc == "tcp6" ||
               transport_lc == "tls6" || transport_lc == "sips6";
    }

	void apply_ipv6_account_config(AccountConfig &acc_cfg, const Config *config, const string &target_uri, const string &transport = "") {
		bool explicit_ipv6_transport = is_ipv6_transport(transport);
		bool ipv6_target = uri_has_ipv6_host(target_uri);

		if (!ipv6_target && !explicit_ipv6_transport) {
			return;
		}
		if (explicit_ipv6_transport) {
			LOG(logINFO) << __FUNCTION__ << ": Enabling IPv6 transport and media";

			acc_cfg.mediaConfig.ipv6Use = PJSUA_IPV6_ENABLED_PREFER_IPV6;
		} else {
			LOG(logINFO) << __FUNCTION__ << ": Enabling IPv6 transport and IPv4 media";

			acc_cfg.mediaConfig.ipv6Use = PJSUA_IPV6_ENABLED_PREFER_IPV4;
		}

		if (!config->ip_cfg.bound_address.empty()) {
			acc_cfg.mediaConfig.transportConfig.boundAddress = config->ip_cfg.bound_address;
		}
		if (!config->ip_cfg.public_address.empty()) {
			acc_cfg.mediaConfig.transportConfig.publicAddress = config->ip_cfg.public_address;
		}
	}
} // namespace

Action::Action(Config *cfg) : config{cfg} {
	init_actions_params();
	std::cout<<"Prepared for Action!\n";
}

vector<ActionParam> Action::get_params(string name) {
	if (name.compare("call") == 0) return do_call_params;
	else if (name.compare("register") == 0) return do_register_params;
	else if (name.compare("wait") == 0) return do_wait_params;
	else if (name.compare("accept") == 0) return do_accept_params;
	else if (name.compare("alert") == 0) return do_alert_params;
	else if (name.compare("codec") == 0) return do_codec_params;
	else if (name.compare("turn") == 0) return do_turn_params;
	else if (name.compare("message") == 0) return do_message_params;
	else if (name.compare("accept_message") == 0) return do_accept_message_params;
	vector<ActionParam> empty_params;
	return empty_params;
}

string Action::get_env(string env) {
	if (const char* val = std::getenv(env.c_str())) {
		std::string s(val);
		return s;
	} else {
		return "";
	}
}

bool Action::set_param(ActionParam &param, const char *val) {
	bool subst {false};
	const char *tmp_val;

	if (!val) {
		return false;
	}

	LOG(logINFO) <<__FUNCTION__<< " param name:" << param.name << " val:" << val;

	// Safe string comparison with length validation
	if (strlen(val) >= 7 && strncmp(val,"VP_ENV_",7) == 0) {
		LOG(logINFO) << __FUNCTION__ << ": " << param.name << " " << val << " substitution override:" << get_env(val);

		subst = true;
	}

	if (param.type == APType::apt_bool) {
		if (subst) {
			tmp_val = get_env(val).c_str();
		} else {
			tmp_val = val;
		}
		param.b_val = stob(tmp_val);
	} else if (param.type == APType::apt_integer) {
		if (subst) {
			param.i_val = safe_atoi(get_env(val).c_str());
		} else {
			param.i_val = safe_atoi(val);
		}
	} else if (param.type == APType::apt_float) {
		if (subst) {
			param.f_val = safe_atof(get_env(val).c_str());
		} else {
			param.f_val = safe_atof(val);
		}
	} else {
		// String parameters - apply input sanitization
		if (subst) {
			param.s_val = sanitize_string_param(get_env(val));
		} else {
		    param.s_val = sanitize_string_param(std::string(val));
		}
	}
	return true;
}

bool Action::set_param_by_name(vector<ActionParam> *params, const string& name, const char *val) {
	for (auto &param : *params) {
		if (param.name.compare(name) == 0) {
			return set_param(param, val);
		}
	}
	return false;
}

void Action::init_actions_params() {
	// do_call
	do_call_params.push_back(ActionParam("caller", true, APType::apt_string));
	do_call_params.push_back(ActionParam("from", true, APType::apt_string));
	do_call_params.push_back(ActionParam("callee", true, APType::apt_string));
	do_call_params.push_back(ActionParam("to_uri", true, APType::apt_string));
	do_call_params.push_back(ActionParam("label", false, APType::apt_string));
	do_call_params.push_back(ActionParam("username", false, APType::apt_string));
	do_call_params.push_back(ActionParam("auth_username", false, APType::apt_string));
	do_call_params.push_back(ActionParam("password", false, APType::apt_string));
	do_call_params.push_back(ActionParam("realm", false, APType::apt_string));
	do_call_params.push_back(ActionParam("transport", false, APType::apt_string));
	do_call_params.push_back(ActionParam("expected_cause_code", false, APType::apt_integer));
	do_call_params.push_back(ActionParam("wait_until", false, APType::apt_string));
	do_call_params.push_back(ActionParam("max_duration", false, APType::apt_integer));
	do_call_params.push_back(ActionParam("repeat", false, APType::apt_integer));
	do_call_params.push_back(ActionParam("max_ring_duration", false, APType::apt_integer));
	do_call_params.push_back(ActionParam("expected_duration", false, APType::apt_integer));
	do_call_params.push_back(ActionParam("expected_duration", false, APType::apt_string));
	do_call_params.push_back(ActionParam("expected_setup_duration", false, APType::apt_integer));
	do_call_params.push_back(ActionParam("expected_setup_duration", false, APType::apt_string));
	do_call_params.push_back(ActionParam("expected_codec", false, APType::apt_string));
	do_call_params.push_back(ActionParam("min_mos", false, APType::apt_float));
	do_call_params.push_back(ActionParam("rtp_stats", false, APType::apt_bool));
	do_call_params.push_back(ActionParam("late_start", false, APType::apt_bool));
	do_call_params.push_back(ActionParam("srtp", false, APType::apt_string));
	do_call_params.push_back(ActionParam("force_contact", false, APType::apt_string));
	do_call_params.push_back(ActionParam("hangup", false, APType::apt_integer));
	do_call_params.push_back(ActionParam("cancel", false, APType::apt_integer));
	do_call_params.push_back(ActionParam("re_invite_interval", false, APType::apt_integer));
	do_call_params.push_back(ActionParam("play", false, APType::apt_string));
	do_call_params.push_back(ActionParam("record", false, APType::apt_string));
	do_call_params.push_back(ActionParam("record_early", false, APType::apt_bool));
	do_call_params.push_back(ActionParam("play_dtmf", false, APType::apt_string));
	do_call_params.push_back(ActionParam("timer", false, APType::apt_string));
	do_call_params.push_back(ActionParam("proxy", false, APType::apt_string));
	do_call_params.push_back(ActionParam("disable_turn", false, APType::apt_bool));
	do_call_params.push_back(ActionParam("contact_uri_params", false, APType::apt_string));
	// do_register
	do_register_params.push_back(ActionParam("transport", false, APType::apt_string));
	do_register_params.push_back(ActionParam("label", false, APType::apt_string));
	do_register_params.push_back(ActionParam("registrar", false, APType::apt_string));
	do_register_params.push_back(ActionParam("proxy", false, APType::apt_string));
	do_register_params.push_back(ActionParam("realm", false, APType::apt_string));
	do_register_params.push_back(ActionParam("username", false, APType::apt_string));
	do_register_params.push_back(ActionParam("auth_username", false, APType::apt_string));
	do_register_params.push_back(ActionParam("account", false, APType::apt_string));
	do_register_params.push_back(ActionParam("aor", false, APType::apt_string));
	do_register_params.push_back(ActionParam("password", false, APType::apt_string));
	do_register_params.push_back(ActionParam("unregister", false, APType::apt_bool));
	do_register_params.push_back(ActionParam("expected_cause_code", false, APType::apt_integer));
	do_register_params.push_back(ActionParam("reg_id", false, APType::apt_string));
	do_register_params.push_back(ActionParam("instance_id", false, APType::apt_string));
	do_register_params.push_back(ActionParam("srtp", false, APType::apt_string));
	do_register_params.push_back(ActionParam("rewrite_contact", true, APType::apt_bool));
	do_register_params.push_back(ActionParam("disable_turn", false, APType::apt_bool));
	do_register_params.push_back(ActionParam("contact_uri_params", false, APType::apt_string));
	// do_accept
	do_accept_params.push_back(ActionParam("match_account", false, APType::apt_string));
	do_accept_params.push_back(ActionParam("transport", false, APType::apt_string));
	do_accept_params.push_back(ActionParam("label", false, APType::apt_string));
	do_accept_params.push_back(ActionParam("cancel", false, APType::apt_string));
	do_accept_params.push_back(ActionParam("max_duration", false, APType::apt_integer));
	do_accept_params.push_back(ActionParam("ring_duration", false, APType::apt_integer));
	do_accept_params.push_back(ActionParam("expected_duration", false, APType::apt_integer));
	do_accept_params.push_back(ActionParam("expected_duration", false, APType::apt_string));
	do_accept_params.push_back(ActionParam("expected_setup_duration", false, APType::apt_integer));
	do_accept_params.push_back(ActionParam("expected_setup_duration", false, APType::apt_string));
	do_accept_params.push_back(ActionParam("expected_codec", false, APType::apt_string));
	do_accept_params.push_back(ActionParam("response_delay", false, APType::apt_integer));
	do_accept_params.push_back(ActionParam("early_media", false, APType::apt_bool));
	do_accept_params.push_back(ActionParam("wait_until", false, APType::apt_string));
	do_accept_params.push_back(ActionParam("hangup", false, APType::apt_integer));
	do_accept_params.push_back(ActionParam("re_invite_interval", false, APType::apt_integer));
	//do_accept_params.push_back(ActionParam("min_mos", false, APType::apt_float));
	do_accept_params.push_back(ActionParam("rtp_stats", false, APType::apt_bool));
	do_accept_params.push_back(ActionParam("late_start", false, APType::apt_bool));
	do_accept_params.push_back(ActionParam("srtp", false, APType::apt_string));
	do_accept_params.push_back(ActionParam("force_contact", false, APType::apt_string));
	do_accept_params.push_back(ActionParam("play", false, APType::apt_string));
	do_accept_params.push_back(ActionParam("record", false, APType::apt_string));
	do_accept_params.push_back(ActionParam("record_early", false, APType::apt_bool));
	do_accept_params.push_back(ActionParam("code", false, APType::apt_integer));
	do_accept_params.push_back(ActionParam("call_count", false, APType::apt_integer));
	do_accept_params.push_back(ActionParam("reason", false, APType::apt_string));
	do_accept_params.push_back(ActionParam("play_dtmf", false, APType::apt_string));
	do_accept_params.push_back(ActionParam("timer", false, APType::apt_string));
	do_accept_params.push_back(ActionParam("fail_on_accept", false, APType::apt_bool));
	do_accept_params.push_back(ActionParam("disable_turn", false, APType::apt_bool));
	do_accept_params.push_back(ActionParam("expected_cause_code", false, APType::apt_integer));
	// do_wait
	do_wait_params.push_back(ActionParam("ms", false, APType::apt_integer));
	do_wait_params.push_back(ActionParam("complete", false, APType::apt_bool));
	// do_alert
	do_alert_params.push_back(ActionParam("email", false, APType::apt_string));
	do_alert_params.push_back(ActionParam("email_from", false, APType::apt_string));
	do_alert_params.push_back(ActionParam("smtp_host", false, APType::apt_string));
	// do_codec
	do_codec_params.push_back(ActionParam("priority", false, APType::apt_integer));
	do_codec_params.push_back(ActionParam("enable", false, APType::apt_string));
	do_codec_params.push_back(ActionParam("disable", false, APType::apt_string));
	// do_turn
	do_turn_params.push_back(ActionParam("enabled", false, APType::apt_bool));
	do_turn_params.push_back(ActionParam("server", false, APType::apt_string));
	do_turn_params.push_back(ActionParam("username", false, APType::apt_string));
	do_turn_params.push_back(ActionParam("password", false, APType::apt_string));
	do_turn_params.push_back(ActionParam("password_hashed", false, APType::apt_bool));
	do_turn_params.push_back(ActionParam("stun_only", false, APType::apt_bool));
	do_turn_params.push_back(ActionParam("sip_stun_use", false, APType::apt_bool));
	do_turn_params.push_back(ActionParam("media_stun_use", false, APType::apt_bool));
	do_turn_params.push_back(ActionParam("disable_ice", false, APType::apt_bool));
	do_turn_params.push_back(ActionParam("ice_trickle", false, APType::apt_bool));
	// do_message
	do_message_params.push_back(ActionParam("from", true, APType::apt_string));
	do_message_params.push_back(ActionParam("to_uri", true, APType::apt_string));
	do_message_params.push_back(ActionParam("text", true, APType::apt_string));
	do_message_params.push_back(ActionParam("username", true, APType::apt_string));
	do_message_params.push_back(ActionParam("password", true, APType::apt_string));
	do_message_params.push_back(ActionParam("realm", false, APType::apt_string));
	do_message_params.push_back(ActionParam("label", true, APType::apt_string));
	do_message_params.push_back(ActionParam("expected_cause_code", false, APType::apt_integer));
	// do_accept_message
	do_accept_message_params.push_back(ActionParam("account", false, APType::apt_string));
	do_accept_message_params.push_back(ActionParam("transport", false, APType::apt_string));
	do_accept_message_params.push_back(ActionParam("label", false, APType::apt_string));
	do_accept_message_params.push_back(ActionParam("message_count", false, APType::apt_integer));
}

void setTurnConfigAccount(AccountConfig &acc_cfg, Config *cfg, bool disable_turn) {
	if (!cfg) {
		LOG(logERROR) <<__FUNCTION__<<" Config pointer is null";
		return;
	}

	turn_config_t *turn_config = &cfg->turn_config;

	if (!turn_config->enabled) {
		LOG(logINFO) <<__FUNCTION__<<" STUN/TURN/ICE: config globally disabled" << std::endl;

		acc_cfg.natConfig.turnEnabled = false;
		acc_cfg.natConfig.iceEnabled = false;

		return;
	}

	if (disable_turn) {
		LOG(logINFO) <<__FUNCTION__<<" Explicitly disable STUN/TURN/ICE for this account";

		acc_cfg.natConfig.sipStunUse = PJSUA_STUN_USE_DISABLED;
		acc_cfg.natConfig.mediaStunUse = PJSUA_STUN_USE_DISABLED;
		acc_cfg.natConfig.turnEnabled = false;
		acc_cfg.natConfig.iceEnabled = false;

		return;
	}

	if (turn_config->stun_only) {
		if (turn_config->server.empty()) {
			LOG(logERROR) <<__FUNCTION__<<" STUN server string is empty";
			return;
		}

		char* srv_name_tmp = (char*)(turn_config->server).data();
		if (!srv_name_tmp) {
			LOG(logERROR) <<__FUNCTION__<<" STUN server data() returned null";
			return;
		}

		pj_str_t srv_list[] = { pj_str(srv_name_tmp) };
		pjsua_update_stun_servers(1, srv_list, 1);

		LOG(logINFO) <<__FUNCTION__<<" STUN only: pushing " << turn_config->server << " as a STUN server";

		if (!turn_config->sip_stun_use && turn_config->media_stun_use) {
			LOG(logINFO) <<__FUNCTION__<<" STUN only: enabled without SIP or Media";
		}

		if (turn_config->sip_stun_use) {
			acc_cfg.natConfig.sipStunUse = PJSUA_STUN_USE_DEFAULT;
		} else {
			acc_cfg.natConfig.sipStunUse = PJSUA_STUN_USE_DISABLED;
		}
		if (turn_config->media_stun_use) {
			acc_cfg.natConfig.mediaStunUse = PJSUA_STUN_USE_DEFAULT;
		} else {
			acc_cfg.natConfig.mediaStunUse = PJSUA_STUN_USE_DISABLED;
		}
		acc_cfg.natConfig.sdpNatRewriteUse = false;
		acc_cfg.natConfig.turnEnabled = false;

		return;
	}

	// Here we should have full TURN config
	LOG(logINFO) <<__FUNCTION__<<" STUN/TURN/ICE: enabling for this account";

	acc_cfg.natConfig.turnEnabled = true;
	acc_cfg.natConfig.iceEnabled = true;
	acc_cfg.natConfig.iceAggressiveNomination = true;
	acc_cfg.natConfig.turnServer = turn_config->server;
	acc_cfg.natConfig.turnUserName = turn_config->username;

	acc_cfg.natConfig.turnPassword = turn_config->password;
	acc_cfg.natConfig.turnPasswordType = PJ_STUN_PASSWD_PLAIN;
	if (turn_config->password_hashed) {
		acc_cfg.natConfig.turnPasswordType = PJ_STUN_PASSWD_HASHED;
	}

	// ICE for this account
	if (turn_config->disable_ice) {
		LOG(logINFO) << __FUNCTION__ << " disabling ICE for this account";

		acc_cfg.natConfig.iceEnabled = false;
	}

	if (turn_config->ice_trickle) {
		LOG(logINFO) << __FUNCTION__ << " enabling Tricke ICE for this account";

		acc_cfg.natConfig.iceTrickle = PJ_ICE_SESS_TRICKLE_FULL;
		acc_cfg.natConfig.iceAggressiveNomination = false;
	}

// ret.ice_cfg_use = PJSUA_ICE_CONFIG_USE_CUSTOM;
// ret.ice_cfg.enable_ice = natConfig.iceEnabled;
// ret.ice_cfg.ice_max_host_cands = natConfig.iceMaxHostCands;
// ret.ice_cfg.ice_opt.aggressive = natConfig.iceAggressiveNomination;
// ret.ice_cfg.ice_opt.nominated_check_delay = natConfig.iceNominatedCheckDelayMsec;
// ret.ice_cfg.ice_opt.controlled_agent_want_nom_timeout = natConfig.iceWaitNominationTimeoutMsec;
// ret.ice_cfg.ice_no_rtcp = natConfig.iceNoRtcp;
// ret.ice_cfg.ice_always_update = natConfig.iceAlwaysUpdate;
}

void Action::do_register(const vector<ActionParam> &params, const vector<ActionCheck> &checks, const SipHeaderVector &x_headers) {
	string type {"register"};
	string transport {"udp"};
	string label {};
	string registrar {};
	string proxy {};
	string realm {"*"};
	string username {};
	string auth_username {};
	string account_name {};
	string account_full_name {};
	string account_aor {};
	string password {};
	string reg_id {};
	string instance_id {};
	string srtp {};
	string contact_params {};
	int expected_cause_code {200};
	bool unregister {false};
	bool rewrite_contact {false};
	bool disable_turn {false};

	for (auto param : params) {
		if (param.name.compare("transport") == 0) transport = param.s_val;
		else if (param.name.compare("label") == 0) label = param.s_val;
		else if (param.name.compare("registrar") == 0) registrar = param.s_val;
		else if (param.name.compare("proxy") == 0) proxy = param.s_val;
		else if (param.name.compare("realm") == 0 && param.s_val != "") realm = param.s_val;
		else if (param.name.compare("account") == 0) account_name = param.s_val;
		else if (param.name.compare("aor") == 0) account_aor = param.s_val;
		else if (param.name.compare("username") == 0) username = param.s_val;
		else if (param.name.compare("auth_username") == 0) auth_username = param.s_val;
		else if (param.name.compare("password") == 0) password = param.s_val;
		else if (param.name.compare("reg_id") == 0) reg_id = param.s_val;
		else if (param.name.compare("instance_id") == 0) instance_id = param.s_val;
		else if (param.name.compare("unregister") == 0) unregister = param.b_val;
		else if (param.name.compare("rewrite_contact") == 0) rewrite_contact = param.b_val;
		else if (param.name.compare("expected_cause_code") == 0) expected_cause_code = param.i_val;
		else if (param.name.compare("srtp") == 0 && param.s_val.length() > 0) srtp = param.s_val;
		else if (param.name.compare("disable_turn") == 0) disable_turn = param.b_val;
		else if (param.name.compare("contact_uri_params") == 0 && param.s_val.length() > 0) contact_params = param.s_val;
	}

	if (username.empty() || password.empty() || registrar.empty()) {
		LOG(logERROR) << __FUNCTION__ << " missing action parameter" ;
		return;
	}
	vp::tolower(transport);
	string transport_param = normalize_transport_param(transport);

	if (account_name.empty()) {
		account_name = username;
	}
	filter_accountname(&account_name);

	if (auth_username.empty()) {
		auth_username = username;
	}
	if (account_aor.empty()) {
		account_aor = username + "@" + registrar;
	}
	// This should be just internal identifier for program
	account_full_name = account_name + "@" + registrar;

	TestAccount *acc = config->findAccount(account_full_name);

	if (unregister) {
		if (acc) {
			// We should probably create a new test ...
			if (acc->test) acc->test->type = "unregister";
			LOG(logINFO) << __FUNCTION__ << " unregister (" << account_full_name << ")";
			AccountInfo acc_inf = acc->getInfo();
			if (acc_inf.regIsActive) {
				LOG(logINFO) << __FUNCTION__ << " register is active";
				try {
					acc->setRegistration(false);
					acc->unregistering = true;
				} catch (pj::Error& e)  {
					LOG(logERROR) << __FUNCTION__ << " error (" << e.status << "): [" << e.srcFile << "] " << e.reason << std::endl;
				}
			} else {
				LOG(logINFO) << __FUNCTION__ << " register is not active";
			}
			int max_wait_ms = 2000;
			while (acc->unregistering && max_wait_ms >= 0) {
				pj_thread_sleep(10);
				max_wait_ms -= 10;
				// acc_inf = acc->getInfo();
			}
			if (acc->unregistering) {
				LOG(logERROR) << __FUNCTION__ << " error : unregister failed/timeout" << std::endl;
			}
			return;
		}
		LOG(logINFO) << __FUNCTION__ << "unregister: account not found (" << account_full_name << ")" << std::endl;
	}

	Test *test = new Test(config, type);
	test->local_user = username;
	test->remote_user = username;
	test->label = label;
	test->expected_cause_code = expected_cause_code;
	test->from = username;
	test->type = type;
	test->srtp = srtp;

	LOG(logINFO) << __FUNCTION__ << " >> sip:" + account_full_name;

	AccountConfig acc_cfg;

	setTurnConfigAccount(acc_cfg, config, disable_turn);
	apply_ipv6_account_config(acc_cfg, config, registrar, transport);

	TransportId transport_id = select_transport_id(config, transport, registrar);
	if (transport_id == -1 && !transport.empty()) {
		LOG(logERROR) << __FUNCTION__ << ": transport not supported for registrar: " << registrar;
		return;
	}
	if (transport_id != -1) {
		acc_cfg.sipConfig.transportId = transport_id;
	}

	if (reg_id != "" || instance_id != "") {
		LOG(logINFO) << __FUNCTION__ << " reg_id:" << reg_id << " instance_id:" << instance_id;
		if (transport_param == "udp") {
			LOG(logINFO) << __FUNCTION__ << " oubound rfc5626 not supported on transport UDP" << std::endl;
		} else {
			acc_cfg.natConfig.sipOutboundUse = true;
			if (reg_id != "")
				acc_cfg.natConfig.sipOutboundRegId = reg_id;
			if (instance_id != "")
				acc_cfg.natConfig.sipOutboundInstanceId = instance_id;
		}
	} else {
		acc_cfg.natConfig.sipOutboundUse = false;
	}
	for (auto x_hdr : x_headers) {
		acc_cfg.regConfig.headers.push_back(x_hdr);
	}

	if (transport_param == "tcp") {
		acc_cfg.idUri = "sip:" + account_aor + ";transport=tcp";
		acc_cfg.regConfig.registrarUri = "sip:" + registrar + ";transport=tcp";

		LOG(logINFO) << __FUNCTION__ << " SIP TCP idUri:<" << acc_cfg.idUri << "> registrarUri:<" << acc_cfg.regConfig.registrarUri << ">" << std::endl;

		if (!proxy.empty()) {
			acc_cfg.sipConfig.proxies.push_back("sip:" + proxy + ";transport=tcp");

			LOG(logINFO) << __FUNCTION__ << " SIP TCP proxies:<sip:" << proxy  << ";transport=tcp>" << std::endl;
		}
	} else if (transport_param == "tls") {
		if (transport_id == -1) {
			LOG(logERROR) << __FUNCTION__ << " TLS transport not supported";
			return;
		}
		acc_cfg.idUri = "sip:" + account_aor + ";transport=tls";
		acc_cfg.regConfig.registrarUri = "sip:" + registrar + ";transport=tls";

		LOG(logINFO) << __FUNCTION__ << " SIP TLS idUri:<" << acc_cfg.idUri << "> registrarUri:<" << acc_cfg.regConfig.registrarUri << ">" << std::endl;

		if (!proxy.empty()) {
			acc_cfg.sipConfig.proxies.push_back("sip:" + proxy + ";transport=tls");

			LOG(logINFO) << __FUNCTION__ << " SIP TLS proxies:<sip:" << proxy  << ";transport=tls>" << std::endl;
		}
	} else if (transport_param == "sips") {
		if (transport_id == -1) {
			LOG(logERROR) << __FUNCTION__ << " TLS transport not supported";

			return;
		}
		acc_cfg.idUri = "sips:" + account_aor;
		acc_cfg.regConfig.registrarUri = "sips:" + registrar;

		LOG(logINFO) << __FUNCTION__ << " SIPS idUri:<" << acc_cfg.idUri << "> registrarUri:<" << acc_cfg.regConfig.registrarUri << ">" << std::endl;

		if (!proxy.empty()) {
			acc_cfg.sipConfig.proxies.push_back("sips:" + proxy);

			LOG(logINFO) << __FUNCTION__ << " SIP TLS proxies:<sips:" << proxy << ">" << std::endl;
		}
	} else {
		acc_cfg.idUri = "sip:" + account_aor;
		acc_cfg.regConfig.registrarUri = "sip:" + registrar;

		LOG(logINFO) << __FUNCTION__ << " SIP UDP idUri:<" << acc_cfg.idUri << "> registrarUri:<" << acc_cfg.regConfig.registrarUri << ">" << std::endl;

		if (!proxy.empty()) {
			acc_cfg.sipConfig.proxies.push_back("sip:" + proxy);

			LOG(logINFO) << __FUNCTION__ << " SIP UDP proxies:<sip:" << proxy << ">" << std::endl;
		}
	}
	acc_cfg.sipConfig.authCreds.push_back(AuthCredInfo("digest", realm, auth_username, 0, password));
	acc_cfg.natConfig.contactRewriteUse = rewrite_contact;

	acc_cfg.sipConfig.contactUriParams = ";vp_acc=" + account_name;
	if (!contact_params.empty()) {
		acc_cfg.sipConfig.contactUriParams += ";" + contact_params;
	}

	// SRTP for incoming calls
	if (srtp.find("dtls") != std::string::npos) {
		acc_cfg.mediaConfig.srtpUse = PJMEDIA_SRTP_OPTIONAL;
		acc_cfg.mediaConfig.srtpOpt.keyings.push_back(PJMEDIA_SRTP_KEYING_DTLS_SRTP);

		LOG(logINFO) << __FUNCTION__ << " adding DTLS-SRTP capabilities";
	}
	if (srtp.find("sdes") != std::string::npos) {
		acc_cfg.mediaConfig.srtpUse = PJMEDIA_SRTP_OPTIONAL;
		acc_cfg.mediaConfig.srtpOpt.keyings.push_back(PJMEDIA_SRTP_KEYING_SDES);

		LOG(logINFO) << __FUNCTION__ << " adding SDES capabilities";
	}
	if (srtp.find("force") != std::string::npos) {
		acc_cfg.mediaConfig.srtpUse = PJMEDIA_SRTP_MANDATORY;

		LOG(logINFO) << __FUNCTION__ << " Forcing encryption";
	}

	if (!acc) {
		acc = config->createAccount(acc_cfg);
	} else {
		acc->modify(acc_cfg);
	}
	acc->setTest(test);
	acc->account_name = account_name;
}

void Action::do_accept(const vector<ActionParam> &params, const vector<ActionCheck> &checks, const pj::SipHeaderVector &x_headers) {
	string type {"accept"};
	string account_name {};
	string transport {};
	string label {};
	string play {default_playback_file};
	string recording {};
	bool record_early {false};
	string play_dtmf {};
	string timer {};
	string cancel_behavoir {};
	//float min_mos {0.0};
	int max_duration {0};
	int ring_duration {0};
	int early_media {false};
	int hangup_duration {0};
	int expected_duration {0};
	int expected_setup_duration {0};
	DurationRange expected_duration_range;
	DurationRange expected_setup_duration_range;
	string expected_codec {""};
	int re_invite_interval {0};
	call_state_t wait_until {INV_STATE_NULL};
	bool rtp_stats {false};
	bool late_start {false};
	bool fail_on_accept {false};
	bool disable_turn {false};
	string srtp {"none"};
	string force_contact {};
	int code {200};
	int expected_cause_code {200};
	int call_count {-1};
	int response_delay {0};
	string reason {};
	string contact_params {};

	for (auto param : params) {
		if (param.name.compare("match_account") == 0) account_name = param.s_val;
		else if (param.name.compare("transport") == 0) transport = param.s_val;
		else if (param.name.compare("play") == 0 && param.s_val.length() > 0) play = param.s_val;
		else if (param.name.compare("record") == 0) recording = param.s_val;
		else if (param.name.compare("record_early") == 0) record_early = param.b_val;
		else if (param.name.compare("play_dtmf") == 0 && param.s_val.length() > 0) play_dtmf = param.s_val;
		else if (param.name.compare("timer") == 0 && param.s_val.length() > 0) timer = param.s_val;
		else if (param.name.compare("code") == 0) code = param.i_val;
		else if (param.name.compare("expected_cause_code") == 0) expected_cause_code = param.i_val;
		else if (param.name.compare("call_count") == 0) call_count = param.i_val;
		else if (param.name.compare("reason") == 0 && param.s_val.length() > 0) reason = param.s_val;
		else if (param.name.compare("label") == 0 && param.s_val.length() > 0) label = param.s_val;
		else if (param.name.compare("max_duration") == 0) max_duration = param.i_val;
		else if (param.name.compare("ring_duration") == 0) ring_duration = param.i_val;
		else if (param.name.compare("expected_duration") == 0) {
			if (param.type == APType::apt_integer) {
				expected_duration = param.i_val;
				expected_duration_range = DurationRange(param.i_val);
			} else if (param.type == APType::apt_string && param.s_val.length() > 0) {
				expected_duration_range = parseDurationRange(param.s_val);
				expected_duration = expected_duration_range.getSingleValue();
			}
		}
		else if (param.name.compare("expected_setup_duration") == 0) {
			if (param.type == APType::apt_integer) {
				expected_setup_duration = param.i_val;
				expected_setup_duration_range = DurationRange(param.i_val);
			} else if (param.type == APType::apt_string && param.s_val.length() > 0) {
				expected_setup_duration_range = parseDurationRange(param.s_val);
				expected_setup_duration = expected_setup_duration_range.getSingleValue();
			}
		}
		else if (param.name.compare("expected_codec") == 0) expected_codec = param.s_val;
		else if (param.name.compare("early_media") == 0) early_media = param.b_val;
		else if (param.name.compare("fail_on_accept") == 0) fail_on_accept = param.b_val;
		else if (param.name.compare("disable_turn") == 0) disable_turn = param.b_val;
		//else if (param.name.compare("min_mos") == 0) min_mos = param.f_val;
		else if (param.name.compare("rtp_stats") == 0) rtp_stats = param.b_val;
		else if (param.name.compare("srtp") == 0 && param.s_val.length() > 0) srtp = param.s_val;
		else if (param.name.compare("force_contact") == 0) force_contact = param.s_val;
		else if (param.name.compare("late_start") == 0) late_start = param.b_val;
		else if (param.name.compare("wait_until") == 0) wait_until = get_call_state_from_string(param.s_val);
		else if (param.name.compare("hangup") == 0) hangup_duration = param.i_val;
		else if (param.name.compare("cancel") == 0) cancel_behavoir = param.s_val;
		else if (param.name.compare("re_invite_interval") == 0) re_invite_interval = param.i_val;
		else if (param.name.compare("response_delay") == 0) response_delay = param.i_val;
		else if (param.name.compare("contact_uri_params") == 0 && param.s_val.length() > 0) contact_params = param.s_val;
	}

	if (account_name.empty()) {
		LOG(logERROR) << __FUNCTION__ << " missing action parameters <match_account>" ;
		config->total_tasks_count += 100;

		return;
	}
	filter_accountname(&account_name);

	vp::tolower(transport);
	string transport_param = normalize_transport_param(transport);

	std::transform(expected_codec.begin(), expected_codec.end(), expected_codec.begin(), ::tolower);

	TestAccount *acc = config->findAccount(account_name);
	if (!acc || !force_contact.empty()) {
		AccountConfig acc_cfg;

		setTurnConfigAccount(acc_cfg, config, disable_turn);
		apply_ipv6_account_config(acc_cfg, config, account_name, transport);

		if (!force_contact.empty()){
			LOG(logINFO) << __FUNCTION__ << ":do_accept:force_contact:" << force_contact << "\n";
			acc_cfg.sipConfig.contactForced = force_contact;
		}

		TransportId transport_id = select_transport_id(config, transport, account_name);
		if (transport_id == -1 && !transport.empty()) {
			LOG(logERROR) << __FUNCTION__ << ": transport not supported for account: " << account_name;
			return;
		}
		if (transport_id != -1) {
			acc_cfg.sipConfig.transportId = transport_id;
		}
		if (transport_param == "sips") {
			if (transport_id == -1) {
				LOG(logERROR) <<__FUNCTION__<<": TLS transport not supported.";
				return;
			}
			acc_cfg.idUri = "sips:" + account_name;
		} else {
			acc_cfg.idUri = "sip:" + account_name;
		}
		if (!timer.empty()) {
			if (timer.compare("inactive") == 0) {
				acc_cfg.callConfig.timerUse = PJSUA_SIP_TIMER_INACTIVE;
			} else if (timer.compare("optionnal") == 0) {
				acc_cfg.callConfig.timerUse = PJSUA_SIP_TIMER_OPTIONAL;
			} else if (timer.compare("required") == 0) {
				acc_cfg.callConfig.timerUse = PJSUA_SIP_TIMER_REQUIRED;
			} else if (timer.compare("always") == 0) {
				acc_cfg.callConfig.timerUse = PJSUA_SIP_TIMER_ALWAYS;
			}
			LOG(logINFO) << __FUNCTION__ << ":session timer["<<timer<<"]: "<< acc_cfg.callConfig.timerUse ;
		}

		if (!contact_params.empty()) {
			acc_cfg.sipConfig.contactUriParams = ";" + contact_params;
		}

		// SRTP
		if (srtp.find("dtls") != std::string::npos) {
			acc_cfg.mediaConfig.srtpOpt.keyings.push_back(PJMEDIA_SRTP_KEYING_DTLS_SRTP);
			acc_cfg.mediaConfig.srtpUse = PJMEDIA_SRTP_OPTIONAL;

			LOG(logINFO) << __FUNCTION__ << " adding DTLS-SRTP capabilities";
		}
		if (srtp.find("sdes") != std::string::npos) {
			acc_cfg.mediaConfig.srtpOpt.keyings.push_back(PJMEDIA_SRTP_KEYING_SDES);
			acc_cfg.mediaConfig.srtpUse = PJMEDIA_SRTP_OPTIONAL;

			LOG(logINFO) << __FUNCTION__ << " adding SDES capabilities";
		}
		if (srtp.find("force") != std::string::npos) {
			acc_cfg.mediaConfig.srtpUse = PJMEDIA_SRTP_MANDATORY;

			LOG(logINFO) << __FUNCTION__ << " Forcing encryption";
		}

		if (acc) {
			acc->modify(acc_cfg);
		} else {
			acc = config->createAccount(acc_cfg);
		}
	}

	if (fail_on_accept) {
		config->total_tasks_count -= 1;
		LOG(logINFO) << __FUNCTION__ << " decreasing task counter to " << config->total_tasks_count << " due to this accept should not happen";
	}

	if (expected_cause_code < 100 || expected_cause_code > 700) {
		expected_cause_code = 200;
	}

	if (code < 100 || code > 700) {
		code = 200;
	}

	acc->hangup_duration = hangup_duration;
	acc->re_invite_interval = re_invite_interval;
	acc->response_delay = response_delay;
	acc->max_duration = max_duration;
	acc->ring_duration = ring_duration;
	acc->accept_label = label;
	acc->rtp_stats = rtp_stats;
	acc->late_start = late_start;
	acc->play = play;
	acc->recording = recording;
	acc->record_early = record_early;
	acc->play_dtmf = play_dtmf;
	acc->timer = timer;
	acc->early_media = early_media;
	acc->wait_state = wait_until;
	acc->reason = reason;
	acc->code = code;
	acc->expected_cause_code = expected_cause_code;
	acc->call_count = call_count;
	acc->x_headers = x_headers;
	acc->checks = checks;
	acc->srtp = srtp;
	acc->force_contact = force_contact;
	acc->cancel_behavoir = cancel_behavoir;
	acc->fail_on_accept	= fail_on_accept;
	acc->disable_turn = disable_turn;
	acc->account_name = account_name;
	acc->expected_duration = expected_duration;
	acc->expected_duration_range = expected_duration_range;
	acc->expected_setup_duration = expected_setup_duration;
	acc->expected_setup_duration_range = expected_setup_duration_range;
	acc->expected_codec = expected_codec;
}


void Action::do_call(const vector<ActionParam> &params, const vector<ActionCheck> &checks, const SipHeaderVector &x_headers) {
	string type {"call"};
	string play {default_playback_file};
	string play_dtmf {};
	string timer {};
	string caller {};
	string from {};
	string callee {};
	string to_uri {};
	string transport {"udp"};
	string username {};
	string auth_username {};
	string password {};
	string realm {"*"};
	string label {};
	string proxy {};
	string srtp {"none"};
	int expected_cause_code {200};
	call_state_t wait_until {INV_STATE_NULL};
	float min_mos {0.0};
	int max_duration {0};
	int max_ring_duration {60};
	int expected_duration {0};
	string expected_codec {""};
	int expected_setup_duration {0};
	DurationRange expected_duration_range;
	DurationRange expected_setup_duration_range;
	int hangup_duration {0};
	int early_cancel {0};
	int re_invite_interval {0};
	int repeat {0};
	string recording {};
	bool record_early {false};
	bool rtp_stats {false};
	bool late_start {false};
	bool disable_turn {false};
	string force_contact {};

	for (auto param : params) {
		if (param.name.compare("callee") == 0) callee = param.s_val;
		else if (param.name.compare("caller") == 0) caller = param.s_val;
		else if (param.name.compare("from") == 0) from = param.s_val;
		else if (param.name.compare("to_uri") == 0) to_uri = param.s_val;
		else if (param.name.compare("transport") == 0) transport = param.s_val;
		else if (param.name.compare("play") == 0 && param.s_val.length() > 0) play = param.s_val;
		else if (param.name.compare("record") == 0) recording = param.s_val;
		else if (param.name.compare("record_early") == 0) record_early = param.b_val;
		else if (param.name.compare("play_dtmf") == 0 && param.s_val.length() > 0) play_dtmf = param.s_val;
		else if (param.name.compare("timer") == 0 && param.s_val.length() > 0) timer = param.s_val;
		else if (param.name.compare("username") == 0) username = param.s_val;
		else if (param.name.compare("auth_username") == 0) auth_username = param.s_val;
		else if (param.name.compare("password") == 0) password = param.s_val;
		else if (param.name.compare("realm") == 0 && param.s_val != "") realm = param.s_val;
		else if (param.name.compare("label") == 0) label = param.s_val;
		else if (param.name.compare("proxy") == 0) proxy = param.s_val;
		else if (param.name.compare("expected_cause_code") == 0) expected_cause_code = param.i_val;
		else if (param.name.compare("wait_until") == 0) wait_until = get_call_state_from_string(param.s_val);
		else if (param.name.compare("min_mos") == 0) min_mos = param.f_val;
		else if (param.name.compare("rtp_stats") == 0) rtp_stats = param.b_val;
		else if (param.name.compare("late_start") == 0) late_start = param.b_val;
		else if (param.name.compare("disable_turn") == 0) disable_turn = param.b_val;
		else if (param.name.compare("srtp") == 0 && param.s_val.length() > 0) srtp = param.s_val;
		else if (param.name.compare("force_contact") == 0) force_contact = param.s_val;
		else if (param.name.compare("max_duration") == 0) max_duration = param.i_val;
		else if (param.name.compare("max_ring_duration") == 0 && param.i_val != 0) max_ring_duration = param.i_val;
		else if (param.name.compare("expected_duration") == 0) {
			if (param.type == APType::apt_integer) {
				expected_duration = param.i_val;
				expected_duration_range = DurationRange(param.i_val);
			} else if (param.type == APType::apt_string && param.s_val.length() > 0) {
				expected_duration_range = parseDurationRange(param.s_val);
				expected_duration = expected_duration_range.getSingleValue();
			}
		}
		else if (param.name.compare("expected_codec") == 0) expected_codec = param.s_val;
		else if (param.name.compare("expected_setup_duration") == 0) {
			if (param.type == APType::apt_integer) {
				expected_setup_duration = param.i_val;
				expected_setup_duration_range = DurationRange(param.i_val);
			} else if (param.type == APType::apt_string && param.s_val.length() > 0) {
				expected_setup_duration_range = parseDurationRange(param.s_val);
				expected_setup_duration = expected_setup_duration_range.getSingleValue();
			}
		}
		else if (param.name.compare("hangup") == 0) hangup_duration = param.i_val;
		else if (param.name.compare("re_invite_interval") == 0) re_invite_interval = param.i_val;
		else if (param.name.compare("early_cancel") == 0) early_cancel = param.i_val;
		else if (param.name.compare("repeat") == 0) repeat = param.i_val;
	}

	if (caller.empty() || callee.empty()) {
		LOG(logERROR) << __FUNCTION__ << ": missing action parameters <callee>/<caller>" ;

		config->total_tasks_count += 100;
		return;
	}
	vp::tolower(transport);
	string transport_param = normalize_transport_param(transport);

	std::transform(expected_codec.begin(), expected_codec.end(), expected_codec.begin(), ::tolower);

	string account_uri {caller};
	if (transport_param != "udp") {
		account_uri = caller + ";transport=" + transport_param;
	}
	TestAccount* acc = config->findAccount(account_uri);
	if (!acc) {
		AccountConfig acc_cfg;

		setTurnConfigAccount(acc_cfg, config, disable_turn);

		string target_uri = to_uri.empty() ? callee : to_uri;
		apply_ipv6_account_config(acc_cfg, config, target_uri, transport);

		if (force_contact != "") {
			LOG(logINFO) << __FUNCTION__ << ":do_call:force_contact:" << force_contact << "\n";
			acc_cfg.sipConfig.contactForced = force_contact;
		}

		if (!timer.empty()) {
			if (timer.compare("inactive") == 0) {
				acc_cfg.callConfig.timerUse = PJSUA_SIP_TIMER_INACTIVE;
			} else if (timer.compare("optionnal") == 0) {
				acc_cfg.callConfig.timerUse = PJSUA_SIP_TIMER_OPTIONAL;
			} else if (timer.compare("required") == 0) {
				acc_cfg.callConfig.timerUse = PJSUA_SIP_TIMER_REQUIRED;
			} else if (timer.compare("always") == 0) {
				acc_cfg.callConfig.timerUse = PJSUA_SIP_TIMER_ALWAYS;
			}
			LOG(logINFO) << __FUNCTION__ << ": session timer[" << timer << "] : " << acc_cfg.callConfig.timerUse ;
		}

		TransportId transport_id = select_transport_id(config, transport, target_uri);
		if (transport_id == -1 && !transport.empty()) {
			LOG(logERROR) << __FUNCTION__ << ": transport not supported for target: " << target_uri;
			return;
		}
		if (transport_id != -1) {
			acc_cfg.sipConfig.transportId = transport_id;
		}

		if (transport_param == "tcp") {
			acc_cfg.idUri = "sip:" + account_uri;

			LOG(logINFO) << __FUNCTION__ << " Account TCP idUri: <" << acc_cfg.idUri << ">" << std::endl;

			if (!proxy.empty()) {
				acc_cfg.sipConfig.proxies.push_back("sip:" + proxy + ";transport=tcp");

				LOG(logINFO) << __FUNCTION__ << " Account TCP proxies: <sip:" << proxy << ";transport=tcp>" << std::endl;
			}
		} else if (transport_param == "tls") {
			if (transport_id == -1) {
				LOG(logERROR) << __FUNCTION__ << ": TLS transport not supported" ;

				return;
			}
			acc_cfg.idUri = "sip:" + account_uri;

			LOG(logINFO) << __FUNCTION__ << " Account TLS idUri: <" << acc_cfg.idUri << ">" << std::endl;

			if (!proxy.empty()) {
				acc_cfg.sipConfig.proxies.push_back("sip:" + proxy + ";transport=tls");

				LOG(logINFO) << __FUNCTION__ << " Account TLS proxies: <sip:" << proxy << ";transport=tls>" << std::endl;
			}
		} else if (transport_param == "sips") {
			if (transport_id == -1) {
				LOG(logERROR) << __FUNCTION__ << ": sips(TLS) transport not supported" ;

				return;
			}
			acc_cfg.idUri = "sips:" + account_uri;

			LOG(logINFO) << __FUNCTION__ << " Account SIPS idUri: <" << acc_cfg.idUri << ">" << std::endl;

			if (!proxy.empty()) {
				acc_cfg.sipConfig.proxies.push_back("sips:" + proxy);

				LOG(logINFO) << __FUNCTION__ << " Account SIPS proxies: <sips:" << proxy << ">" << std::endl;
			}
		} else {
			acc_cfg.idUri = "sip:" + account_uri;

			LOG(logINFO) << __FUNCTION__ << " Account UDP idUri: <" << acc_cfg.idUri << ">" << std::endl;

			if (!proxy.empty()) {
				acc_cfg.sipConfig.proxies.push_back("sip:" + proxy);

				LOG(logINFO) << __FUNCTION__ << " Account UDP proxies: <sip:" << proxy << ">" << std::endl;
			}
		}

		if (!from.empty()) {
			if (!((from.find("sip:") != std::string::npos) || (from.find("sips:") != std::string::npos))) {
				if (transport == "sips") {
					from = "sips:" + from;
				} else {
					from = "sip:" + from;
				}
			}

			acc_cfg.idUri = from;

			LOG(logINFO) << __FUNCTION__ << " Account idUri: <" << acc_cfg.idUri << ">" << std::endl;
		}

		if (!username.empty() || !auth_username.empty()) {
			if (password.empty()) {
				LOG(logERROR) << __FUNCTION__ << ": realm specified missing password";

				return;
			}
			if (auth_username.empty()) {
				auth_username = username;
			}
			acc_cfg.sipConfig.authCreds.push_back(AuthCredInfo("digest", realm, auth_username, 0, password));
		}

		// SRTP
		if (srtp.find("dtls") != std::string::npos) {
			acc_cfg.mediaConfig.srtpOpt.keyings.push_back(PJMEDIA_SRTP_KEYING_DTLS_SRTP);
			acc_cfg.mediaConfig.srtpUse = PJMEDIA_SRTP_OPTIONAL;

			LOG(logINFO) << __FUNCTION__ << " adding DTLS-SRTP capabilities";
		}
		if (srtp.find("sdes") != std::string::npos) {
			acc_cfg.mediaConfig.srtpOpt.keyings.push_back(PJMEDIA_SRTP_KEYING_SDES);
			acc_cfg.mediaConfig.srtpUse = PJMEDIA_SRTP_OPTIONAL;

			LOG(logINFO) << __FUNCTION__ << " adding SDES capabilities";
		}
		if (srtp.find("force") != std::string::npos) {
			acc_cfg.mediaConfig.srtpUse = PJMEDIA_SRTP_MANDATORY;

			LOG(logINFO) << __FUNCTION__ << " Forcing encryption";
		}

		acc = config->createAccount(acc_cfg);

		LOG(logINFO) << __FUNCTION__ << ": session timer["<<timer<<"] :"<< acc_cfg.callConfig.timerUse << " TURN: "<< acc_cfg.natConfig.turnEnabled;
	}

	do {
		Test *test = new Test(config, type);
		memset(&test->sip_latency, 0, sizeof(sipLatency));
		test->wait_state = wait_until;

		if (test->wait_state != INV_STATE_NULL) {
			test->state = VPT_RUN_WAIT;
		}

		test->expected_duration = expected_duration;
		test->expected_duration_range = expected_duration_range;
		test->expected_setup_duration = expected_setup_duration;
		test->expected_setup_duration_range = expected_setup_duration_range;
		test->expected_codec = expected_codec;
		test->label = label;
		test->play = play;
		test->play_dtmf = play_dtmf;
		test->min_mos = min_mos;
		test->max_duration = max_duration;
		test->max_ring_duration = max_ring_duration;
		test->hangup_duration = hangup_duration;
		test->re_invite_interval = re_invite_interval;
		test->re_invite_next = re_invite_interval;
		test->recording = recording;
		test->record_early = record_early;
		test->rtp_stats = rtp_stats;
		test->late_start = late_start;
		test->force_contact = force_contact;
		test->srtp = srtp;
		test->early_cancel = early_cancel;
		std::size_t pos = caller.find("@");

		if (pos!=std::string::npos) {
			test->local_user = caller.substr(0, pos);
		}

		pos = callee.find("@");

		if (pos!=std::string::npos) {
			test->remote_user = callee.substr(0, pos);
		}

		TestCall *call = new TestCall(acc);
		config->calls.push_back(call);

		call->test = test;
		test->expected_cause_code = expected_cause_code;
		test->from = caller;
		test->to = callee;
		test->type = type;
		acc->calls.push_back(call);
		CallOpParam prm(true);

		for (auto x_hdr : x_headers) {
			prm.txOption.headers.push_back(x_hdr);
		}

		prm.opt.audioCount = 1;
		prm.opt.videoCount = 0;

		LOG(logINFO) << "call->test:" << test << " " << call->test->type;
		LOG(logINFO) << "calling :" << callee;

		if (transport_param == "tls") {
			if (!to_uri.empty() && !safe_string_starts_with(to_uri, "sip")) {
				to_uri = "sip:" + to_uri + ";transport=tls";
			}
			try {
				call->makeCall("sip:" + callee + ";transport=tls", prm, to_uri);
			} catch (pj::Error& e)  {
				LOG(logERROR) << __FUNCTION__ << " error (" << e.status << "): [" << e.srcFile << "] " << e.reason << std::endl;
			}
		} else if (transport_param == "sips") {
			if (!to_uri.empty() && !safe_string_starts_with(to_uri, "sips")) {
				to_uri = "sips:" + to_uri;
			}
			try {
				call->makeCall("sips:" + callee, prm, to_uri);
			} catch (pj::Error& e)  {
				LOG(logERROR) << __FUNCTION__ << " error (" << e.status << "): [" << e.srcFile << "] " << e.reason << std::endl;
			}
		} else if (transport_param == "tcp") {
			if (!to_uri.empty() && !safe_string_starts_with(to_uri, "sip")) {
				to_uri = "sip:" + to_uri + ";transport=tcp";
			}
			try {
				call->makeCall("sip:" + callee + ";transport=tcp", prm, to_uri);
			} catch (pj::Error& e)  {
				LOG(logERROR) << __FUNCTION__ << " error (" << e.status << "): [" << e.srcFile << "] " << e.reason << std::endl;
			}
		// Default UDP transport
		} else {
			if (!to_uri.empty() && !safe_string_starts_with(to_uri, "sip")) {
				to_uri = "sip:" + to_uri;
			}
			try {
				call->makeCall("sip:" + callee, prm, to_uri);
			} catch (pj::Error& e)  {
				LOG(logERROR) << __FUNCTION__ << " error (" << e.status << "): [" << e.srcFile << "] " << e.reason << std::endl;
			}
		}
		pj_gettimeofday(&test->sip_latency.inviteSentTs);
		repeat -= 1;
	} while (repeat >= 0);
}

void Action::do_turn(const vector<ActionParam> &params) {
	bool enabled {false};
	string server {};
	string username {};
	string password {};
	bool password_hashed {false};
	bool stun_only {false};
	bool sip_stun_use {false};
	bool media_stun_use {false};
	bool disable_ice {false};
	bool ice_trickle {false};

	for (auto param : params) {
		if (param.name.compare("enabled") == 0) enabled = param.b_val;
		else if (param.name.compare("server") == 0) server = param.s_val;
		else if (param.name.compare("username") == 0) username = param.s_val;
		else if (param.name.compare("password") == 0) password = param.s_val;
		else if (param.name.compare("password_hashed") == 0) password_hashed = param.b_val;
		else if (param.name.compare("sip_stun_use") == 0) sip_stun_use = param.b_val;
		else if (param.name.compare("media_stun_use") == 0) media_stun_use = param.b_val;
		else if (param.name.compare("stun_only") == 0) stun_only = param.b_val;
		else if (param.name.compare("disable_ice") == 0) disable_ice = param.b_val;
		else if (param.name.compare("ice_trickle") == 0) ice_trickle = param.b_val;
	}
	LOG(logINFO) << __FUNCTION__ << " enabled["<<enabled<<"] server["<<server<<"] username["<<username<<"] password["<<password<<"]:"<<password_hashed;

	config->turn_config.enabled = enabled;
	config->turn_config.server = server;
	config->turn_config.password_hashed = password_hashed;
	if (!username.empty())
		config->turn_config.username = username;
	if (!password.empty())
		config->turn_config.password = password;
	config->turn_config.media_stun_use = media_stun_use;
	config->turn_config.sip_stun_use = sip_stun_use;
	config->turn_config.stun_only = stun_only;
	config->turn_config.disable_ice = disable_ice;
	config->turn_config.ice_trickle = ice_trickle;
}


void Action::do_message(const vector<ActionParam> &params, const vector<ActionCheck> &checks, const SipHeaderVector &x_headers) {
	string to_uri {};
	string from {};
	string text {};
	string transport {"udp"};
	string username {};
	string password {};
	string realm {"*"};
	string label {};
	int expected_cause_code {200};
	for (auto param : params) {
		if (param.name.compare("from") == 0) from = param.s_val;
		else if (param.name.compare("to_uri") == 0) to_uri = param.s_val;
		else if (param.name.compare("text") == 0) text = param.s_val;
		else if (param.name.compare("transport") == 0) transport = param.s_val;
		else if (param.name.compare("username") == 0) username = param.s_val;
		else if (param.name.compare("password") == 0) password = param.s_val;
		else if (param.name.compare("realm") == 0 && param.s_val != "") realm = param.s_val;
		else if (param.name.compare("label") == 0) label = param.s_val;
		else if (param.name.compare("expected_cause_code") == 0) expected_cause_code = param.i_val;
	}

    string buddy_uri = "<sip:" + to_uri + ">";
    BuddyConfig bCfg;
    bCfg.uri = buddy_uri;
	bCfg.subscribe = false;

	TestAccount *acc = config->findAccount(from);

	string account_uri = from;
	string target_uri = to_uri;

	vp::tolower(transport);
	string transport_param = normalize_transport_param(transport);

	if (transport_param != "udp") {
		 account_uri = "sip:" + account_uri + ";transport=" + transport_param;
		 to_uri = to_uri + ";transport=" + transport_param;
	} else {
		 account_uri = "sip:" + account_uri;
	}
	if (!acc) { // account not found, creating one
		AccountConfig acc_cfg;

		apply_ipv6_account_config(acc_cfg, config, target_uri, transport);

		TransportId transport_id = select_transport_id(config, transport, target_uri);
		if (transport_id == -1 && !transport.empty()) {
			LOG(logERROR) << __FUNCTION__ << ": transport not supported for target: " << target_uri;
			return;
		}
		if (transport_id != -1) {
			acc_cfg.sipConfig.transportId = transport_id;
		}

		acc_cfg.idUri = account_uri;
		acc_cfg.sipConfig.authCreds.push_back(AuthCredInfo("digest", realm, username, 0, password));

		LOG(logINFO) <<__FUNCTION__ << ": create buddy account_uri:" << account_uri << "\n";

		acc = config->createAccount(acc_cfg);
	}

	Buddy buddy;
	Account& account = *acc;
    buddy.create(account, bCfg);
    // buddy.delete();
	string type{"message"};

	Test *test = new Test(config, type);
	test->local_user = username;
	test->remote_user = username;
	test->label = label;
	test->expected_cause_code = expected_cause_code;
	test->from = username;
	test->type = type;
	acc->test = test;

	SendInstantMessageParam param;
	param.content = text;
	param.txOption.targetUri = buddy_uri;

	LOG(logINFO) <<__FUNCTION__ << "sending... InstantMessage\n";

	buddy.sendInstantMessage(param);

	LOG(logINFO) <<__FUNCTION__ << ": sent InstantMessage\n";
}

void Action::do_accept_message(const vector<ActionParam> &params, const vector<ActionCheck> &checks, const pj::SipHeaderVector &x_headers) {
	string type {"accept_message"};
	string account_name {};
	string transport {};
	int code {200};
	int message_count {1};
	string label {};
	string reason {};
	string expected_message {};
	for (auto param : params) {
		if (param.name.compare("account") == 0) account_name = param.s_val;
		else if (param.name.compare("transport") == 0) transport = param.s_val;
		else if (param.name.compare("code") == 0) code = param.i_val;
		else if (param.name.compare("message_count") == 0) message_count = param.i_val;
		else if (param.name.compare("reason") == 0 && param.s_val.length() > 0) reason = param.s_val;
		else if (param.name.compare("label") == 0) label = param.s_val;
		else if (param.name.compare("expected_message") == 0) expected_message = param.s_val;
	}

	if (account_name.empty()) {
		LOG(logERROR) <<__FUNCTION__<< " missing action parameters <account>";

		config->total_tasks_count += 100;
		return;
	}
	vp::tolower(transport);
	string transport_param = normalize_transport_param(transport);

	TestAccount *acc = config->findAccount(account_name);
	AccountConfig acc_cfg;
	if (!acc) {

		apply_ipv6_account_config(acc_cfg, config, account_name, transport);
		TransportId transport_id = select_transport_id(config, transport, account_name);

		if (transport_id == -1 && !transport.empty()) {
			LOG(logERROR) << __FUNCTION__ << ": transport not supported for account: " << account_name;
			return;
		}
		if (transport_id != -1) {
			acc_cfg.sipConfig.transportId = transport_id;
		}
		if (transport_param == "sips") {
			if (transport_id == -1) {
				LOG(logERROR) << __FUNCTION__ << ": TLS transport not supported.";
				return;
			}
			acc_cfg.idUri = "sips:" + account_name;
		} else {
			acc_cfg.idUri = "sip:" + account_name;
		}

		if (acc) {
			acc->modify(acc_cfg);
		} else {
			acc = config->createAccount(acc_cfg);
		}
	}
	acc->accept_label = label;
	acc->reason = reason;
	acc->code = code;
	acc->message_count = message_count;
	acc->x_headers = x_headers;
	acc->checks = checks;

	Test *test = new Test(config, type);
	test->checks = checks;
	test->expected_cause_code = 200;
	acc->testAccept = test;
}

void Action::do_codec(const vector<ActionParam> &params) {
	string enable {};
	int priority {0};
	string disable {};
	for (auto param : params) {
		if (param.name.compare("enable") == 0) enable = param.s_val;
		else if (param.name.compare("priority") == 0) priority = param.i_val;
		else if (param.name.compare("disable") == 0) disable = param.s_val;
	}
	LOG(logINFO) << __FUNCTION__ << " enable["<<enable<<"] with priority["<<priority<<"] disable["<<disable<<"]";
	if (!config->ep) {
		LOG(logERROR) << __FUNCTION__ << " PJSIP endpoint not available";
		return;
	}
	if (!disable.empty())
		config->ep->setCodecs(disable, 0);
	if (!enable.empty())
		config->ep->setCodecs(enable, priority);
}

void Action::do_alert(const vector<ActionParam> &params) {
	string email {};
	string email_from {};
	string smtp_host {};
	for (auto param : params) {
		if (param.name.compare("email") == 0) email = param.s_val;
		else if (param.name.compare("email_from") == 0) email_from = param.s_val;
		else if (param.name.compare("smtp_host") == 0) smtp_host = param.s_val;
	}
	LOG(logINFO) << __FUNCTION__ << "email to:"<<email<< " from:"<<email_from;
	config->alert_email_to = email;
	config->alert_email_from = email_from;
	config->alert_server_url = smtp_host;
}

void Action::do_wait(const vector<ActionParam> &params) {
	int duration_ms = 0;
	bool complete_all = false;

	for (auto param : params) {
		if (param.name.compare("ms") == 0) {
			duration_ms = param.i_val;
		}
		if (param.name.compare("complete") == 0) {
			complete_all = param.b_val;
		}
	}

	LOG(logINFO) << __FUNCTION__ << " processing duration_ms:" << duration_ms << " complete all tests:" << complete_all;

	bool completed = false;
	int tests_running = 0;
	bool status_update = true;

	while (!completed) {

		// insert any incomming call received in another thread.
		config->new_calls_lock.lock();
		if (!config->new_calls.empty()) {
			auto it = config->new_calls.begin();
			config->calls.push_back(std::move(*it));
			config->new_calls.erase(it);
		}
		config->new_calls_lock.unlock();

		for (auto & account : config->accounts) {
			AccountInfo acc_inf = account->getInfo();

			if (account->test && account->test->state == VPT_DONE) {
				delete account->test;
				account->test = NULL;
			} else if (account->test) {
				tests_running += 1;
			}
			// accept/call_count, are considered "tests_running" when maximum duration is either not specified or reached.
			if (account->call_count > 0 && (duration_ms > 0 || duration_ms == -1)) {
				tests_running += 1;
			}
			// accept/message_count, are considered "tests_running" when maximum duration is either not specified or reached.
			if (account->message_count > 0 && (duration_ms > 0 || duration_ms == -1)) {
				tests_running += 1;
			}
		}

		// prevent calls destruction while parsing looking at them
		config->checking_calls.lock();

		for (auto & call : config->calls) {
			if (call->test && call->test->state == VPT_DONE) {
				//CallInfo ci = call->getInfo();
				//if (ci.state == PJSIP_INV_STATE_DISCONNECTED)
				//LOG(logINFO) << "delete call test["<<call->test<<"] = " << config->removeCall(call);
				continue;
			} else if (call->test) {
				CallInfo ci = call->getInfo();
				if (status_update) {
					LOG(logDEBUG) << __FUNCTION__ << ": [call][" << call->getId() << "][test][" << (ci.role==0?"CALLER":"CALLEE") << "]["
						     << ci.callIdString << "][" << ci.remoteUri << "][" << ci.stateText << "|" << ci.state << "]duration["
						     << ci.connectDuration.sec << ">=" << call->test->hangup_duration<< "]";
				}
				if (ci.state == PJSIP_INV_STATE_CALLING || ci.state == PJSIP_INV_STATE_EARLY || ci.state == PJSIP_INV_STATE_INCOMING)  {
					Test *test = call->test;
					if (test->response_delay > 0 && ci.totalDuration.sec >= test->response_delay && ci.state == PJSIP_INV_STATE_INCOMING) {
						CallOpParam prm;
						// Explicitly answer with 100
						CallOpParam prm_100;

						prm_100.statusCode = PJSIP_SC_TRYING;
						call->answer(prm_100);

						if (test->ring_duration > 0) {

							prm.statusCode = PJSIP_SC_RINGING;
							if (test->early_media) {
								prm.statusCode = PJSIP_SC_PROGRESS;
							}

							call->answer(prm);
						} else {
							prm.reason = "OK";
							if (test->code) {
								prm.statusCode = test->code;
							} else {
								prm.statusCode = PJSIP_SC_OK;
							}
							call->answer(prm);
						}
						LOG(logINFO) << " Answering call[" << call->getId() << "] with " << prm.statusCode << " on call time: " << ci.totalDuration.sec;

					} else if (test->ring_duration > 0 && ci.totalDuration.sec >= (test->ring_duration + test->response_delay)) {
						CallOpParam prm;
						prm.reason = "OK";

						if (test->code) {
							prm.statusCode = test->code;
						} else {
							prm.statusCode = PJSIP_SC_OK;
						}

						LOG(logINFO) << " Answering call[" << call->getId() << "] with " << test->code << " on call time: " << ci.totalDuration.sec;

						call->answer(prm);
					} else if (test->max_ring_duration && (test->max_ring_duration + test->response_delay) <= ci.totalDuration.sec) {
						LOG(logINFO) << __FUNCTION__ << "[cancelling:call][" << call->getId() << "][test][" << (ci.role==0?"CALLER":"CALLEE") << "]["
						     << ci.callIdString << "][" << ci.remoteUri << "][" << ci.stateText << "|" << ci.state << "]duration["
						     << ci.totalDuration.sec << ">=(" << test->max_ring_duration << " + " << test->response_delay << ")]";
						CallOpParam prm(true);
						try {
							pj_gettimeofday(&test->sip_latency.byeSentTs);
							call->hangup(prm);
						} catch (pj::Error& e)  {
							if (e.status != 171140) {
								LOG(logERROR) << __FUNCTION__ << " error :" << e.status;
							}
						}
					}
				} else if (ci.state == PJSIP_INV_STATE_CONFIRMED) {
					std::string res = "call[" + std::to_string(ci.lastStatusCode) + "] reason[" + ci.lastReason + "]";
					call->test->connect_duration = ci.connectDuration.sec;
					call->test->setup_duration = ci.totalDuration.sec - ci.connectDuration.sec;
					call->test->result_cause_code = (int)ci.lastStatusCode;
					call->test->reason = ci.lastReason;
					// check re-invite
					if (call->test->re_invite_interval && ci.connectDuration.sec >= call->test->re_invite_next){
						if (ci.state == PJSIP_INV_STATE_CONFIRMED) {
							CallOpParam prm(true);
							prm.opt.audioCount = 1;
							prm.opt.videoCount = 0;
							LOG(logINFO) << __FUNCTION__ << " re-invite : call in PJSIP_INV_STATE_CONFIRMED" ;
							try {
								call->reinvite(prm);
								call->test->re_invite_next = call->test->re_invite_next + call->test->re_invite_interval;
							} catch (pj::Error& e)  {
								if (e.status != 171140) {
									LOG(logERROR) << __FUNCTION__ << " error (" << e.status << "): [" << e.srcFile << "] " << e.reason << std::endl;
								}
							}
						}
					}
					// check hangup
					if (call->test->hangup_duration && ci.connectDuration.sec >= call->test->hangup_duration){
						if (ci.state == PJSIP_INV_STATE_CONFIRMED) {
							CallOpParam prm(true);
							LOG(logINFO) << "hangup : call in PJSIP_INV_STATE_CONFIRMED" ;
							try {
								pj_gettimeofday(&call->test->sip_latency.byeSentTs);
								call->hangup(prm);
							} catch (pj::Error& e)  {
								if (e.status != 171140) {
									LOG(logERROR) << __FUNCTION__ << " error (" << e.status << "): [" << e.srcFile << "] " << e.reason << std::endl;
								}
							}
						}
						call->test->update_result();
					}
				}
				if (complete_all || call->test->state == VPT_RUN_WAIT) {
					tests_running += 1;
				}
			}
		}

		for (auto it = config->tests_with_rtp_stats.begin(); it != config->tests_with_rtp_stats.end();) {
			if ((*it)->rtp_stats_ready) {
				(*it)->update_result();
				LOG(logINFO) << __FUNCTION__ << " erase test at position:" << std::distance(config->tests_with_rtp_stats.begin(), it);
				it = config->tests_with_rtp_stats.erase(it);
			} else {
				tests_running += 1;
				++it;
 			}
		}
		// calls, can now be destroyed
		config->checking_calls.unlock();

		if (tests_running == 0 && complete_all) {
			LOG(logINFO) << __FUNCTION__ << LOG_COLOR_ERROR << ": action[wait] no more tests are running, exiting... " << LOG_COLOR_END;
			completed = true;
		}

		if (duration_ms <= 0 && duration_ms != -1) {
			LOG(logINFO) << __FUNCTION__ << LOG_COLOR_ERROR << ": action[wait] overall duration exceeded, exiting... " << LOG_COLOR_END;
			completed = true;
		}

		if (tests_running > 0 && complete_all) {
			if (status_update) {
				LOG(logINFO) << __FUNCTION__ <<LOG_COLOR_ERROR<<": action[wait] active account tests or call tests in run_wait["<<tests_running<<"] <<<<"<<LOG_COLOR_END;
				status_update = false;
			}
			tests_running = 0;

			if (duration_ms > 0) {
				duration_ms -= 100;
			}

			pj_thread_sleep(100);
		} else {
			if (status_update) {
				LOG(logINFO) << __FUNCTION__ <<LOG_COLOR_ERROR<<": action[wait] just wait for " << duration_ms <<  " ms" <<LOG_COLOR_END;
				status_update = false;
			}
			if (duration_ms > 0) {
				duration_ms -= 10;
				pj_thread_sleep(10);
				continue;
			} else if (duration_ms == -1) {
				pj_thread_sleep(10);
				continue;
			}

			completed = true;
			LOG(logINFO) << __FUNCTION__ << ": completed";
		}
	}
}
