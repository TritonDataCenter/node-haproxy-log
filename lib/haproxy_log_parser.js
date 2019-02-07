/* vim: set ts=8 sts=8 sw=8 noet: */
/*
 * haproxy_log_parser.js: transform stream to parse haproxy logs
 */

var mod_assert = require('assert-plus');
var mod_util = require('util');
var mod_stream = require('stream');
var VE = require('verror');

var CLS_NOT_SPACE = '[^ ]+';
var CLS_DIGITS = '[0-9]+';
var CLS_IPADDR = '[:a-f0-9\\.]+';
var CLS_DIGITS_OR_MINUS_ONE = '[0-9]+|-1';

function
build_matcher()
{
	var re_str = '';
	var groups = [];

	var group = function (re, name, type) {
		re_str += '(' + re + ')';
		groups.push({ n: name, t: type, i: groups.length + 1 });
	};

	var non = function (re) {
		re_str += re;
	};

	/*
	 * Construct a regular expression that matches the basic HAProxy HTTP
	 * log format without any of the optional fields.
	 */
	non('^');
	group(CLS_NOT_SPACE, 'syslog_date', 'date');
	non(' ');
	group(CLS_NOT_SPACE, 'syslog_hostname');
	non(' haproxy\\[');
	group(CLS_DIGITS, 'pid', 'number');
	non('\\]: ');
	group(CLS_IPADDR, 'client_ip', 'ip');
	non(':');
	group(CLS_DIGITS, 'client_port', 'number');
	non(' \\[');
	group(CLS_NOT_SPACE, 'accept_date');
	non('\\] ');
	group(CLS_NOT_SPACE, 'frontend_name');
	non(' ');
	group('[^ /]+', 'backend_name');
	non('/');
	group(CLS_NOT_SPACE, 'server_name');

	// The "Tq" and others are a haproxy 1.5-ism
	// (https://cbonte.github.io/haproxy-dconv/configuration-1.5.html#8.2.3)
	// vs. "TR" in haproxy 1.7
	// (https://cbonte.github.io/haproxy-dconv/1.7/configuration.html#8.2.3)
	non(' ');
	group(CLS_DIGITS_OR_MINUS_ONE, 'Tq', 'number');
	non('/')
	group(CLS_DIGITS_OR_MINUS_ONE, 'Tw', 'number');
	non('/')
	group(CLS_DIGITS_OR_MINUS_ONE, 'Tc', 'number');
	non('/')
	group(CLS_DIGITS_OR_MINUS_ONE, 'Tr', 'number');
	non('/')
	group('\\+?', 'Tt_logasap', 'boolean');
	group(CLS_DIGITS, 'Tt', 'number');

	non(' ');
	group(CLS_DIGITS_OR_MINUS_ONE, 'status_code', 'number');
	non(' ');
	group(CLS_DIGITS, 'bytes_read', 'number');
	non(' - - ');
	group('....', 'termination_state', 'termination_state');

	non(' ');
	group(CLS_DIGITS, 'actconn', 'number');
	non('/')
	group(CLS_DIGITS, 'feconn', 'number');
	non('/')
	group(CLS_DIGITS, 'beconn', 'number');
	non('/')
	group(CLS_DIGITS, 'src_conn', 'number');
	non('/')
	group('\\+?', 'retries_redispatch', 'boolean');
	group(CLS_DIGITS, 'retries', 'number');

	non(' ');
	group(CLS_DIGITS, 'srv_queue', 'number');
	non('/')
	group(CLS_DIGITS, 'backend_queue', 'number');


	non(' "');
	group('[^"]*', 'http_request');
	non('"$');

	return ({
		re_str: re_str,
		re: new RegExp(re_str),
		groups: groups
	});
}

/*
 * HAProxy logs appear under some conditions to represent IPv4 addresses as
 * IPv4-mapped IPv6 addresses; i.e., "::ffff:A.B.C.D".  If the address is in
 * this form, return just the IPv4 portion of the address string; otherwise,
 * return the entire string unmodified.
 */
function
normalise_ip(ip)
{
	var m = ip.match(/^::ffff:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$/);

	if (m) {
		return (m[1]);
	}

	return (ip);
}

/*
 * The HAProxy documentation uses the term "server" to refer to the backend
 * server processes in the pool.  As the proxy itself is also a server process
 * of sorts, we avoid using "SERVER" at all in these messages, preferring
 * "BACKEND" for the backend server and "PROXY" for the proxy itself.
 *
 * These cause and state codes were gleaned from section 8.5, "Session state at
 * disconnection" from the HAProxy 1.5 configuration documentation.
 */
var TERMINATION_CAUSES = {
	'C': 'CLIENT_ABORT',
	'S': 'BACKEND_ABORT',
	'D': 'BACKEND_ABORT_OR_REJECT',
	'P': 'PROXY_ABORT_OR_REJECT',
	'L': 'HANDLED_BY_PROXY',
	'R': 'RESOURCE_EXHAUSTION',
	'I': 'INTERNAL_ERROR',
	'D': 'FAILOVER',
	'U': 'FAILBACK',
	'K': 'ADMIN_ABORT',
	'c': 'CLIENT_DATA_TIMEOUT',
	's': 'BACKEND_DATA_TIMEOUT',
	'-': 'NORMAL'
};

var STATES_AT_CLOSE = {
	'R': 'PRE_CLIENT_REQUEST',
	'Q': 'QUEUED_FOR_BACKEND',
	'C': 'PRE_BACKEND_CONNECTION',
	'H': 'WAITING_FOR_RESPONSE_HEADERS',
	'D': 'DATA_TRANSFER',
	'L': 'FINAL_DATA_TRANSFER',
	'T': 'TARPITTED',
	'-': 'NORMAL'
};

function
parse_termination_state(v)
{
	var o = {
		raw: v,
		termination_cause: 'UNKNOWN (' + v[0] + ')',
		state_at_close: 'UNKNOWN (' + v[1] + ')',
		persistence_cookie_client: 'UNKNOWN (' + v[2] + ')',
		persistence_cookie_server: 'UNKNOWN (' + v[3] + ')'
	};

	if (v[2] === '-') {
		o.persistence_cookie_client = 'N/A';
	}
	if (v[3] === '-') {
		o.persistence_cookie_server = 'N/A';
	}

	if (TERMINATION_CAUSES[v[0]]) {
		o.termination_cause = TERMINATION_CAUSES[v[0]];
	}

	if (STATES_AT_CLOSE[v[1]]) {
		o.state_at_close = STATES_AT_CLOSE[v[1]];
	}

	return (o);
}

function
HAProxyLogTransform()
{
	var self = this;

	mod_stream.Transform.call(self, { highWaterMark: 0, objectMode: true });

	self.hlt_matcher = build_matcher();
}
mod_util.inherits(HAProxyLogTransform, mod_stream.Transform);

HAProxyLogTransform.prototype._transform = function (l, _, done) {
	var self = this;

	mod_assert.string(l, 'l');
	mod_assert.func(done, 'done');

	var m = self.hlt_matcher.re.exec(l);
	var out = {};

	if (!m) {
		var re = self.hlt_matcher.re;
		setImmediate(done,
		    VE('malformed log line: "%s" (does not match %s)',
			l, re));
		return;
	}

	for (var i = 0; i < self.hlt_matcher.groups.length; i++) {
		var g = self.hlt_matcher.groups[i];
		var v = m[g.i];

		/*
		 * Switch on the group type, to decide how to store this value:
		 */
		switch (g.t) {
		case 'number':
			out[g.n] = parseInt(v, 10);
			break;
		case 'date':
			out[g.n] = new Date(v);
			break;
		case 'termination_state':
			out[g.n] = parse_termination_state(v);
			break;
		case 'ip':
			out[g.n] = normalise_ip(v);
			break;
		case 'boolean':
			out[g.n] = Boolean(v);
			break;
		default:
			out[g.n] = m[g.i];
			break;
		}
	}

	/*
	 * Because of the log line format, it can be difficult to represent an
	 * empty value in many of the fields.  We know of several special
	 * strings that essentially represent an empty value, so check for
	 * those and replace them with null:
	 */
	if (out.server_name === '<NOSRV>') {
		out.server_name = null;
	}
	if (out.http_request === '<BADREQ>') {
		out.http_request = null;
	}

	self.push(out);
	setImmediate(done);
};

module.exports = {
	HAProxyLogTransform: HAProxyLogTransform
};
