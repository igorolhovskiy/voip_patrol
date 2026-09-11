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

#include "check.hh"
#include "pj_util.hpp"
#include <regex>

bool check_regex(string m, string e) {
	std::istringstream ss(m);
	std::string line;
	std::regex re(e);

	while (std::getline(ss, line)) {
		// Remove CRLF leftovers
		line.pop_back();

		if (std::regex_match(line, re)) {
			LOG(logINFO) << __FUNCTION__ << " [" << e << "] ~= [" << line << "]";

			return true;
		}
		LOG(logINFO) << __FUNCTION__ << " [" << e << "] != [" << line << "]";
	}
	LOG(logINFO) << __FUNCTION__ << " [" << e << "] No matches found!";

	return false;
}


void check_checks(vector<ActionCheck> &checks, pjsip_msg* msg, const string& message) {
	std::string method = pj2Str(msg->line.req.method.name);

	LOG(logINFO) << __FUNCTION__ << ": " << method;

	for (vector<ActionCheck> :: iterator check = checks.begin(); check != checks.end(); ++check) {
		// Message checks
		if (check->type == "message") {
			if (!check->regex.empty()) {
				if (method != check->method) {
					continue;
				}
				if (check_regex(message, check->regex)) {
					check->result = true;

					LOG(logINFO) << __FUNCTION__ << ":  Message matched regex";
				}
				if (check->fail_on_match) {
					check->result = not check->result;

					LOG(logINFO) << __FUNCTION__ << ": fail_on_match is true, inverting result to " << check->result;
				}
			}
			continue;
		}

		// Header checks
		if (check->type == "header") {
			if (method != check->method) {
				continue;
			}

			if (check->hdr.hName == "") {
				continue;
			}

			// Special check for RURI header. It's a first line of the message
			if (check->hdr.hName == "RURI") {
				std::istringstream tmp_ss(message);
				std::string ruri;
				std::getline(tmp_ss, ruri);
				// Remove CRLF leftovers
				ruri.pop_back();

				if (check->hdr.hValue == ruri) {
					check->result = true;

					LOG(logINFO) << __FUNCTION__ << " Checking RURI ok: [" << ruri << "] == [" << check->hdr.hValue <<"]";
				} else {
					if (check->hdr.hValue.length() >= 6 && check->hdr.hValue.substr(0,6) == "regex/") {
						std::string header_value_regex = check->hdr.hValue.substr(6);

						if (check_regex(ruri, header_value_regex)) {
							check->result = true;

							LOG(logINFO) << __FUNCTION__ << " Checking RURI ok: [" << ruri << "] ~= [" << header_value_regex <<"]";
						}
					} else {
						LOG(logINFO) << __FUNCTION__ << " Checking RURI failed: [" << ruri << "] != [" << check->hdr.hValue <<"]";
					}
				}

				if (check->fail_on_match) {
					check->result = not check->result;

					LOG(logINFO) << __FUNCTION__ << ": fail_on_match is true, inverting result to " << check->result;
				}
				continue;
			} // R-URI

			// start of pasted code
			LOG(logINFO) << __FUNCTION__ << " check-header:" << check->hdr.hName << " " << check->hdr.hValue << " count=" << check->count;

			pj_str_t header_name;
			header_name.slen = strlen(check->hdr.hName.c_str());
			header_name.ptr = (char*) check->hdr.hName.c_str();

			// Determine if we need to match all headers or a specific count
			bool match_all = (check->count == "all");
			int required_count = match_all ? 0 : std::stoi(check->count);
			int matched_count = 0;
			int total_found = 0;

			// Iterate through all matching headers
			pjsip_hdr* s_hdr = nullptr;
			while ((s_hdr = (pjsip_hdr*) pjsip_msg_find_hdr_by_name(msg, (const pj_str_t *) &header_name, s_hdr == nullptr ? nullptr : s_hdr->next)) != nullptr) {
				total_found++;

				SipHeader SHdr;
				SHdr.fromPj(s_hdr);

				bool value_matches = false;

				if (check->hdr.hValue == "" || check->hdr.hValue == SHdr.hValue) {
					LOG(logINFO) << __FUNCTION__ << " header found and value is matching:" << SHdr.hName << " " << SHdr.hValue;
					value_matches = true;
				} else {
				// Check if we have regex in pattern
				if (check->hdr.hValue.length() >= 6 && check->hdr.hValue.substr(0,6) == "regex/") {
					std::string header_value_regex = check->hdr.hValue.substr(6);

					if (check_regex(SHdr.hValue, header_value_regex)) {
					LOG(logINFO) << __FUNCTION__ << " header " << SHdr.hName << " found and value is matching in regex style: " << SHdr.hValue << " =~ " << header_value_regex;
					value_matches = true;
					}
				} else {
					LOG(logINFO) << __FUNCTION__ << " header " << SHdr.hName << " found and value is not matching: " << SHdr.hValue << " != " << check->hdr.hValue;
				}
				}

				if (value_matches) {
					matched_count++;
				} else if (match_all) {
				// If we need all to match and this one doesn't, fail early
				break;
				}
			}

			// Evaluate the result based on count requirement
			if (match_all) {
				// All headers must match (and at least one must exist)
				check->result = (total_found > 0 && matched_count == total_found);
				LOG(logINFO) << __FUNCTION__ << " match_all: found=" << total_found << " matched=" << matched_count << " result=" << check->result;
			} else {
				// At least the required count must match
				check->result = (matched_count >= required_count);
				LOG(logINFO) << __FUNCTION__ << " required=" << required_count << " matched=" << matched_count << " result=" << check->result;
			}

			if (check->fail_on_match) {
				check->result = not check->result;
				LOG(logINFO) << __FUNCTION__ << ": fail_on_match is true, inverting result to " << check->result;
			}
			
			// end of pasted code

			continue;
		}

		LOG(logWARNING) << __FUNCTION__ << ": unknown check type: " << check->type;
	}
}
