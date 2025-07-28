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

#ifndef VOIP_PATROL_ACTION_H
#define VOIP_PATROL_ACTION_H

#include "voip_patrol.hh"
#include "check.hh"
#include <pjsua2.hpp>
#include <stdexcept>
#include <cctype>
#include <climits>

class Config;
class ActionCheck;

using namespace std;

enum class APType { apt_integer, apt_string, apt_float, apt_bool };

struct ActionParam {
	ActionParam(const string& name, bool required, APType type, const string& s_val="", int i_val=0, float f_val=0.0, bool b_val=false)
                 : type(type), required(required), name(name), i_val(i_val), s_val(s_val), f_val(f_val) , b_val(b_val) {}
	APType type {APType::apt_integer};
	string name;
	int i_val;
	string s_val;
	float f_val;
	bool b_val;
	bool required;
};

// Safe string-to-number conversion functions with input validation
int safe_atoi(const char* str, int default_value = 0);
float safe_atof(const char* str, float default_value = 0.0f);

// Safe string operations with bounds checking
bool safe_string_starts_with(const std::string& str, const std::string& prefix);
std::string sanitize_string_param(const std::string& input, size_t max_length = 512);

class Action {
	public:
			Action(Config *cfg);
			vector<ActionParam> get_params(string);
			bool set_param(ActionParam&, const char *val);
			bool set_param_by_name(vector<ActionParam> *params, const string& name, const char *val=nullptr);
			void do_call(const vector<ActionParam> &params, const vector<ActionCheck> &checks, const pj::SipHeaderVector &x_headers);
			void do_accept(const vector<ActionParam> &params, const vector<ActionCheck> &checks, const pj::SipHeaderVector &x_headers);
			void do_wait(const vector<ActionParam> &params);
			void do_register(const vector<ActionParam> &params, const vector<ActionCheck> &checks, const pj::SipHeaderVector &x_headers);
			void do_alert(const vector<ActionParam> &params);
			void do_codec(const vector<ActionParam> &params);
			void do_turn(const vector<ActionParam> &params);
			void do_message(const vector<ActionParam> &params, const vector<ActionCheck> &checks, const pj::SipHeaderVector &x_headers);
			void do_accept_message(const vector<ActionParam> &params, const vector<ActionCheck> &checks, const pj::SipHeaderVector &x_headers);
			void set_config(Config *);
			Config* get_config();
	private:
			string get_env(string);
			void init_actions_params();
			vector<ActionParam> do_call_params;
			vector<ActionParam> do_register_params;
			vector<ActionParam> do_wait_params;
			vector<ActionParam> do_accept_params;
			vector<ActionParam> do_alert_params;
			vector<ActionParam> do_codec_params;
			vector<ActionParam> do_turn_params;
			vector<ActionParam> do_message_params;
			vector<ActionParam> do_accept_message_params;
			Config* config;
};

#endif
