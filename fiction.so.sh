#!/bin/bash
# The Fiction(R) Library, powered by insane people (C) 2025-2026
shopt -s nullglob
set -m
if ! (return 0 2>/dev/null); then
	FICTION_PATH="$PWD/"
	readonly is_sourced=0
else
	FICTION_PATH="${BASH_SOURCE//fiction.so.sh}"
	readonly is_sourced=1
fi
ms="${EPOCHREALTIME//[.,]}"
init_time="${ms::-3}"
[[ -v FICTION_META ]] || FICTION_META=""
_green=$'\e[38;5;2m'
_red=$'\e[38;5;1m'
_yellow=$'\e[38;5;3m'
_white=$'\e[38;5;255m'
_bold=$'\e[1m'
_gray=$'\e[38;5;240m'
_nc=$'\e[0m'
OUT_PATH="/dev/shm/.fiction_out"
[[ "$FICTION_NESTED" == true ]] && return
declare -gA Fiction=(
	[version]="v1.0.0-prerelease"
	[path]="${FICTION_PATH}"
)

#workerargs="-x"
declare -gA FictionRoute=()
declare -ga FictionDynamicRoute
declare -gA FictionResponse=(
	[head]="$FICTION_META" 
)

declare -gA FictionRequest=()
declare -gA FictionRequestHeaders FictionRequestQuery FictionRequestBody FictionRequestCookie FictionResponseHeaders FictionResponseCookie
declare -gA FictionModule=( 
	# Example on adding module: 
	# FictionModule[bashx]="${Fiction[path]}/modules/bashx/bashx"
)

declare -gA status_codes=(
	[101]="101 Switching Protocols"
	[200]="200 OK"
	[201]="201 Created"
	[202]="201 Accepted"
	[204]="204 No Content"
	[301]="301 Moved Permanently"
	[302]="302 Found"
	[400]="400 Bad Request"
	[401]="401 Unauthorized"
	[403]="403 Forbidden"
	[404]="404 Not Found"
	[405]="405 Method Not Allowed"
	[410]="410 Length Required"
	[415]="415 Unsupported Media Type"
	[418]="I'm a teapot"
	[429]="Too Many Requests"
	[500]="500 Internal Server Error"
	[501]="501 Not Implemented"
	[502]="502 Bad gateway"
	[503]="503 Service Unavailable"
	[502]="505 Gateway Timeout"
)

# Code structure
# - subshell
# - time_ms
# - parse_sec
# - catch_job
# - _spawn
# - _console
# - clean
# - _hash
# - _encode
# - _decode
# - _regex
# - @cache
# - @prerender
# - mktmpDir
# - _error
# - _warn
# - urldecode 
# - uuidgen
# - fiction.response_code.set
# - rename_fn
# - fiction.router
# - fiction.worker
# - fiction.addServerAction
# - fiction.addMeta
# - fiction.header.set
# - fiction.session
# - fiction.response.cookie.set
# - fiction.session.set
# - fiction.respond
# - fiction.404
# - fiction.500
# - fiction
# - fiction.serve
# - fiction.serveDynamic
# - fiction.serveCGI
# - fiction.redirect
# - fiction.serveFile
# - fiction.serveDir
# - fiction.server
# - _hotreload
# - _build
# - _buildWorker
# - _modulesLoader
# - _helpmsg
# - declare_objects

# Helper functions
function subshell() {
	local var="$1"
	#printf -v "$var" "$(${@:2})"
#  return
	${@:2} >"$OUT_PATH"
	read -r -d $'\0' $var <"$OUT_PATH"
}

function time_ms {
	ms="${EPOCHREALTIME//[.,]/}"
	ms="${ms::-3}"
}

function parse_sec {
	T="$1"
	local D=$((T/60/60/24))
	local H=$((T/60/60%24))
	local M=$((T/60%60))
	local S=$((T%60))
	local out=""
	(( D > 0 )) && { (( D > 1 )) && out+="$D days " || out+="$D day "; }
	(( H > 0 )) && { (( H > 1 )) && out+="$H hours " || out+="$H hour "; }
	(( M > 0 )) && { (( M > 1 )) && out+="$M minutes " || out+="$M minute "; }
	(( D > 0 || H > 0 || M > 0 && S > 0 )) && out+='and '
	(( S > 0 )) && { (( S > 1 )) && out+="$S seconds " || out+="$S second "; }
	[[ -z "$out" ]] && human_readable_time="${T:-0}s" || human_readable_time="${out::-1}"
}

function _read_file() {
	read -r -d $'\0' "$1" <"$2"
}

function profiler {
	snap="${EPOCHREALTIME//[.,]/}"
	snap="${snap::-3}"
	printf "\e[1F%s ms\e[1E       %s\n" "$((snap - snap1))" "$BASH_COMMAND"
	snap1="$snap"
}

declare -A jobs=()
function catch_job {
	#set -x
	local -i codes=0
	#jobs -n >&2
	#echo "$dead_pids" >&2
	#[[ -z "$dead_pids" ]] && return

	subshell updated_jobs jobs -n
	 while read id state code _; do
		case "$state" in
			"Exit") codes+=1 ;;
		esac
	done <<< "$updated_jobs"
	(( codes == 0 )) && return
	for pid in "${!jobs[@]}"; do
		job_name="${jobs[$pid]}"
		[[ -z "${job_name}" ]] && continue
		#_warn "Job '${job_name}' ($pid) exited"
		[ -f /proc/$pid/status ] && continue
		case "$job_name" in
			'') continue ;;
			'network listener'|'threader'|'hot-reload')
			time_ms
			if [[ "$_restart_timestamp" ]] && (( ms - _restart_timestamp < 100 )); then
				_error "Failed to restart '$job_name' ($pid) (job exited too quickly since the last restart)"
				exit 1
			else
				_error "Caught job '$job_name' ($pid) crashing. Trying to restart..."
				unset jobs[$pid]
				time_ms
				_restart_timestamp="$ms"
				_spawn "$job_name" 
			fi 
			;;
		esac
	done
	#set +x
}

function _spawn {
	case "$1" in
	'network listener')
		local address="${Fiction[address]}" port="${Fiction[port]}"
		case "${Fiction[core]:-socat}" in
			bash)
				if "${Fiction[ssl.enabled]:=false}"; then
					_error "HTTPS isn't available in development core. Use ncat or socat for HTTPS server"
					exit 1
				else
					[ ! -f "${FictionModule[accept]}" ] && _error "\`accept\` is not found in ${Fiction[path]}" && return 1;
					enable -f "${FictionModule[accept]}" accept;
					while true; do
						accept -b "$address" -r REMOTE_ADDR "$port";
						if [[ -n "$ACCEPT_FD" ]]; then
							{
								ms="${EPOCHREALTIME//[.,]/}"
								worker_init_time="${ms::-3}"
								fiction.worker "&${ACCEPT_FD}" <&${ACCEPT_FD};
								exec {ACCEPT_FD}>&-;
								if [[ -f "$serverTmpDir/.conns" ]]; then 
									read conns <"$serverTmpDir/.conns"
									case "${conns:-0}" in
										0) echo 1 > "$serverTmpDir/.conns" ;;
										*) echo "$((conns + 1))" > "$serverTmpDir/.conns" ;;
									esac
								fi
							} &
						fi
					done &
					jobs[$!]="$1"
				fi
				;;
			socat)
				which socat >/dev/null || { _error "cannot find socat binary" && return 1; }
				if "${Fiction[ssl.enabled]:=false}"; then
					exec -a "fiction" socat -T10 openssl-listen:"$port",bind="$address",verify=0,${Fiction[ssl.cert]:+cert="${Fiction[ssl.cert]}",}${Fiction[ssl.key]:+key="${Fiction[ssl.key]}",}reuseaddr,fork SYSTEM:"$serverTmpDir/job.sh" &
				else
					exec -a "fiction" socat -T10 TCP-LISTEN:$port,bind="$address",reuseaddr,fork EXEC:"$serverTmpDir/worker.sh" &
				fi
				jobs[$!]="$1"
			;;
			ncat)
				which ncat >/dev/null || { _error "cannot find ncat binary" && return 1; }
				if "${Fiction[ssl.enabled]:=false}"; then
					exec -a "fiction" ncat -klp "$port" -c "$serverTmpDir/worker.sh" --ssl ${Fiction[ssl.cert]:+--ssl-cert "${Fiction[ssl.cert]}"} ${Fiction[ssl.key]:+--ssl-key "${Fiction[ssl.key]}"} -w 10 &
				else
					exec -a "fiction" ncat -klp "$port" -c "$serverTmpDir/worker.sh" -w 10 &
				fi
				jobs[$!]="$1"
			;;
			nc | netcat)
				nc --version 2> 1 > /dev/null && nc_path="nc.traditional" || nc_path="nc";
				which "$nc_path" >/dev/null || { _error "cannot find netcat binary" && return 1; }
				if "${Fiction[ssl.enabled]:=false}"; then
					_error "HTTPS is not supported in legacy netcat mode" 1>&2
				else
					while true; do
							exec -a "fiction" $nc_path -vklp "$port" -e "$serverTmpDir/worker.sh";
							(($? != 0)) && break
					done &
					jobs[$!]="$1"
				fi
			;;
		esac
		;;
	'threader')
		while true; do
			IFS=';' read worker REMOTE_ADDR < $serverTmpDir/.workers
			case "$worker" in
				"") continue ;;
			esac
			OUT_PATH="/dev/shm/.fiction_buf_$worker"
    		{
				ms="${EPOCHREALTIME//[.,]/}"
				worker_init_time="${ms::-3}"
        		#printf "worker: %s\n" "$worker"
        		fiction.worker "/dev/shm/.worker-$worker.in" <"/dev/shm/.worker-$worker.out";
    		} &
		done &
		jobs[$!]="$1"
		;;
	'hot-reload')
		_hotreload &
		jobs[$!]="$1"
		;;
	*) return
	esac
	#[[ "${2::1}" ]] && echo "restarted '$1' ($!)"
}

function _console {
	while sleep 0.1; do
		read -t 1 line;
		case "$line" in
			exit|quit|q|stop) exit ;;
			i|info) fiction ;;
			s|stats|status)
				_read_file proc "/proc/$$/status"
				[[ "$proc" =~ VmRSS:(.*)kB ]] && read rss _ <<< "${BASH_REMATCH[1]}"
				if ((rss > 1024)); then
					builtin printf -v size "%.2f MB" "${rss}e-3"
				else
					builtin printf -v size "%.d KB" "${size}"
				fi
				read conns < "$serverTmpDir/.conns"
				time_ms
				local seconds=$(( (ms - init_time) / 1000))
				parse_sec "$seconds"
				echo "running for $human_readable_time"
				echo "RSS: $size"
				echo "total connections: ${conns:=0}"
				echo "active jobs:"
				for pid in "${!jobs[@]}"; do
					printf "%s" "- ${jobs[$pid]} ($pid)"
					[[ -f "/proc/${pid}/status" ]] && printf "\n" || printf " %s\n" "(exited)"
				done
				;;
		esac
	done
}

clean() {
	echo -e "\nStopping the server..."
	{
		[[ -n "$serverTmpDir" && -d "$serverTmpDir" ]] && rm -rf "$serverTmpDir"
		kill ${!jobs[@]}
		printf "" > "$FICTION_PATH/fiction.lock"
		echo "Waiting for all jobs to exit... (${!jobs[@]})"
		wait ${!jobs[@]}
		
	} 2>/dev/null
	exit
}

function @cache() {
	[ -z "$(declare -F "$1")" ] && return
	while declare -f "$1" | grep -q "{cache}"; do
	local CACHEBLOCK_BEGIN=0
	local CACHEBLOCK_END=0
	local linenum=1
	while IFS= read -r line; do
		if [[ "$line" == *"{cache}"* ]]; then
		CACHEBLOCK_BEGIN="$((linenum + 1))"
		continue
		elif [[ "$line" == *"{/cache}"* ]]; then
		CACHEBLOCK_END="$linenum"
		break
		fi

		linenum=$((linenum + 1))
	done <<<"$(declare -f "$1")"

	local CACHE_DATA="echo \"$(eval $(declare -f "$1" | sed -n "${CACHEBLOCK_BEGIN},${CACHEBLOCK_END}p") | sed 's+"+\\\\"+g')\""
	eval "$(declare -f "$1" | awk -v start="$(($CACHEBLOCK_BEGIN - 1))" -v end="$(($CACHEBLOCK_END + 1))" -v r="$CACHE_DATA" 'NR < start { print; next } NR == start { split(r, a, "\n"); for (i in a) print a[i]; next } NR > end')"
	done

	if [ -z "$DO_NOT_RERUN" ] && subshell func declare -F "$1" && [ -n "$func" ]; then
	DO_NOT_RERUN=1 @cache "\\$1"
	return
	fi
}

function @prerender {
	declare -F "$1" >/dev/null || return
 # @cache "$1" # just in case
	local PRERENDER_DATA="$1(){ 
		cat << '_${1}_EOF'
		$("$1")
_${1}_EOF
	}"
	eval "$PRERENDER_DATA"
}

function _mktmpDir() {
	if [[ -z "$serverTmpDir" ]]; then
	! pidof fiction >/dev/null && [ -d "/dev/shm/.fiction" ] && rm -rf /dev/shm/.fiction/* 2>&1 >/dev/null
	local hex
	subshell hex openssl rand -hex 16
	serverTmpDir="/tmp/.fiction/tmp_$hex"
 
		if ! mkdir -p "$serverTmpDir" 2>&1 >/dev/null; then
			serverTmpDir="/dev/shm/.fiction/tmp_$hex"
			mkdir -p "$serverTmpDir"
		fi
	fi
}

function _error() {
	[[ ${#FUNCNAME[@]} > 1 ]] && echo -n "(${FUNCNAME[1]}) " >&2
	echo "${_red}Error:${_nc} ${1}" >&2
	#[[ "$2" ]] && FUNCTION_ERROR=
}

function _warn() {
	echo -e "${_yellow}⚠ $@${_nc}" >&2
}

__htmlhelper() {
	local file="$1" output=''
	[ -f "$file" ] || return
	_read_file output "$file" 
	if [[ "${output::6}" != '<html>' && "${output::15}" != '<!DOCTYPE html>' ]]; then
		cat <<- EOF 
			<!DOCTYPE html>
			<html>
				<head>
					<meta name="viewport" content="width=device-width, initial-scale=1.0">
						${FictionResponse[head]}$FICTION_META
					</head>
EOF
				[[ "${output}" == *"<body"* ]] && echo "$output" || echo "<body>$output</body>";
				[[ "${Fiction[plugins@v]}" =~ "lucide-icons" ]] && echo '<script>lucide.createIcons();</script>'
		echo "</html>";
	fi >"$file"
}

# https://github.com/dylanaraps/pure-bash-bible#decode-a-percent-encoded-string
urldecode() {
	: "${1//+/ }"
	printf '%b\n' "${_//%/\\x}"
}

# https://gist.github.com/markusfisch/6110640
uuidgen() {
	cat /proc/sys/kernel/random/uuid
}

fiction.response_code.set() {
	FictionResponse["status"]="${status_codes[${1:-200}]:-$1}"
}

rename_fn() {
	local a
	a="$(declare -f "$1")" &&
	eval "function $2 ${a#*"()"}"
	unset -f "$1";
}

function fiction.router() {
	if [[ "${#Fiction[allowed_hostnames]}" > 3 ]]; then
		local host port key
		IFS=':' read host port <<< "${FictionRequestHeaders[host]}"
		[[ -z "$host" ]] && return
		for _ in _; do 
			for key in ${Fiction[allowed_hostnames]:3}; do
				key="${Fiction[allowed_hostnames.$key]}"
				case "$key" in
					"$host") continue 2 ;;
				esac
			done
			fiction.404;
			return;
		done
	fi
	case "${FictionRequest[path]}" in
		*".."*|*"~"*) handled_by="fiction.404"; fiction.404; return ;;
		*"//"*) FictionRequest[path]="${FictionRequest[path]//\/\//\/}" ;;
		*) [[ "${FictionRequest[path]: -1}" != '/' ]] && FictionRequest[path]="${FictionRequest[path]}/" ;;
	esac
	
	local route func route1 func1 m=false path="${FictionRequest[path]}" ou;
	# "$route|$funcname|$type|${content_type}"
	ou="${FictionRoute[$path]}"
	if [[ "$ou" ]]; then
		IFS='|' read route func type contenttype <<< "$ou";
		read func funcargs <<< "$func";
		FICTION_ROUTE="$path";
		handled_by="$func"
		if [[ "$type" == cgi ]]; then
			local headers=;
			SERVER_SOFTWARE="fiction/${Fiction[version]//v}" \
			REQUEST_METHOD="${FictionRequest[method]}" \
			REMOTE_ADDR="$REMOTE_ADDR" \
			FICTION_ROUTE="$path" \
			REQUEST_PATH="$path" \
			CONTENT_LENGTH="${FictionRequestHeaders[content-length]}" \
			SCRIPT_NAME="$func" \
			HTTPS="${Fiction[ssl.enabled]}" \
			SCRIPT_FILENAME="$func" \
			HTTP_USER_AGENT="${FictionRequestHeaders[user-agent]}" \
			HTTP_COOKIE="${FictionRequestHeaders[cookie]}" \
			$func;
		else
			#parsePost
			[[ "$func" == 'echo' ]] && $func "${funcargs//\"/\\\"}" || $func ${funcargs};
			#set +x
		fi
	elif (( "${#FictionDynamicRoute[@]}" != 0 )); then
		for route in "${FictionDynamicRoute[@]}"; do
			IFS='|' read route func type contenttype <<< "$route";
			local regex
			subshell regex sed -e 's#\[[^]]*\]#([^/]+)#g' <<< "$route"
			regex="${regex%/}/?"
			[[ "${FictionRequest[path]}" =~ $regex ]] || continue
			local slugs=$(echo "$route" | grep -oP '\[\K[^]]+(?=\])' | tr '\n' ' ' | sed 's/,$//')
			slugs="${slugs% }" 
			read _ $slugs <<< "${BASH_REMATCH[@]}"
			handled_by="$func"
			$func
			return
		done
		fiction.404
	else
		fiction.404;
	fi
}

function fiction.worker() {
	#set -x
	WORKER_FIFO="$1"
	#trap profiler DEBUG
	local REQUEST_METHOD REQUEST_PATH HTTP_VERSION entry
	read -r REQUEST_METHOD REQUEST_PATH HTTP_VERSION
	HTTP_VERSION="${HTTP_VERSION%%$'\r'}"
	[[ "$HTTP_VERSION" =~ HTTP/[0-9]\.?[0-9]? ]] && HTTP_VERSION="${BASH_REMATCH[0]}" || return
	[[ -z "$REQUEST_METHOD" || -z "$REQUEST_PATH" ]] && return
	FictionRequest=(
		[method]="$REQUEST_METHOD"
		[path]="$REQUEST_PATH"
		[version]="$HTTP_VERSION"
		[addr]="$REMOTE_ADDR"
	)
	local line _h
	while read -r line; do
		line="${line%%$'\r'}"
		[[ -z "$line" ]] && break
		_h="${line%%:*}"
		FictionRequestHeaders["${_h,,}"]="${line#*: }"
	done
	local entry key value
	IFS='?' read -r REQUEST_PATH get <<<"$REQUEST_PATH"
	subshell get urldecode "$get"
	IFS='#' read -r REQUEST_PATH _ <<<"$REQUEST_PATH"

	if [[ "${get::1}" != '' ]]; then 
		IFS='&' read -ra data <<<"$get"
		for entry in "${data[@]}"; do
			FictionRequestQuery["${entry%%=*}"]="${entry#*=}"
		done
	fi

	if [ -n "${FictionRequestHeaders["Cookie"]}" ]; then
		IFS=';' read -ra cookie <<<"${FictionRequestHeaders["cookie"]}"
		#((${#cookie[@]} < 1 )) 
		cookie+=( ${FictionRequestHeaders["cookie"]//;} )
		for entry in ${cookie[@]}; do
			IFS='=' read -r key value <<<"$entry"
			[[ "$key" ]] && FictionRequestCookie["$key"]="${value}"
		done
	fi

	case "${FictionRequest[method]}" in
		"POST"|"PATCH"|"PUT"|"DELETE")
			if ((${FictionRequestHeaders['content-length']:=0} > 0)); then
				local entry content_type="${FictionRequestHeaders["content-type"]}"
				local post_data="";
				case "${Fiction[body.$content_type]}" in
					"{}"|"@A"*|true)
						read -N "${FictionRequestHeaders["content-length"]}" post_data
						#post_data="${post_data%%$'\r'}"
						post_data="${post_data%%$'\n\n'}"
						FictionRequestBodyRaw="${post_data}"
				esac

				if [[ "${Fiction[body.$content_type.parse]}" == true ]]; then
					case "$content_type" in
						"application/x-www-form-urlencoded")
							IFS='&' read -r -a data <<< "$post_data"
							for entry in "${data[@]}"; do
								entry="${entry%%$'\r'}"
								FictionRequestBody["${entry%%=*}"]="${entry#*:}"
							done
							;;
						"application/json")
							[[ "${Fiction[body.application/json.trim]}" == true ]] && json_trim "${post_data}" true true
							json_to_arr "${json_trim_output:-$post_data}" FictionRequestBody "" false true "${Fiction[body.application/json.raw]}"
							;;
					esac
				fi
			fi
		esac

	WORKER_OUT="/dev/shm/.fiction_output_$RANDOM"
	filename="$WORKER_OUT"
	fiction.router
	if [[ "$__fiction_responded" != 1 ]]; then
		_error "'$handled_by' provides no response or any 'fiction.respond' trigger, falling back to 500"; 
		fiction.500 
	fi
	case "${FictionResponse["status"]::3}" in
		'') 
			_error "'$handled_by' provides no response status, falling back to 500"; 
			fiction.500 
			;;
		201|204) local empty_body=1 ;;
		*) local empty_body=0
	esac

	local headers="${!FictionResponseHeaders[@]}"
	local routetype="$type"
	local filetype="$contenttype"
	[[ "$headers" != *"server"* ]] && FictionResponseHeaders[server]="Fiction/${Fiction[version]//v}"

		
	if (( ! empty_body )); then
		if [[ "$headers" == *"Content-Type"* ]]; then 
			FictionResponseHeaders[content-type]="${FictionResponseHeaders[Content-Type]}"
			unset 'FictionResponseHeaders[Content-Type]'
		fi

		subshell filesize wc -c "$filename"
		read size filename <<<"$filesize"
		FictionResponseHeaders["content-length"]="${size:-0}"
		case "${FictionResponseHeaders["content-type"]}" in
		'')
			if [[ -z "$filetype" || "$filetype" == "auto" ]]; then
				FictionResponseHeaders["content-type"]="application/octet-stream"
			else
				FictionResponseHeaders["content-type"]="${filetype}"
			fi
			;;
		text/html)
			[[ "$routetype" != cgi ]] && __htmlhelper "$filename"
		esac
	fi
	
	if [[ "${WORKER_FIFO::1}" == "&" ]]; then
		{
			printf '%s %s\n' "HTTP/1.1" "${FictionResponse["status"]}"
			if [[ "$routetype" != "cgi" ]]; then
				for key in "${!FictionResponseHeaders[@]}"; do printf '%s: %s\n' "${key,,}" "${FictionResponseHeaders[$key]}"; done
				for value in "${FictionResponseCookie[@]}"; do printf 'Set-Cookie: %s\n' "$value"; done
				(( ! empty_body )) && printf "\n"
			fi
			(( size == 0 || empty_body )) || cat "$filename"
		} >&"${WORKER_FIFO:1}"
	else
		{
			printf '%s %s\n' "HTTP/1.1" "${FictionResponse["status"]}"
			if [[ "$routetype" != "cgi" ]]; then
				for key in "${!FictionResponseHeaders[@]}"; do printf '%s: %s\n' "${key,,}" "${FictionResponseHeaders[$key]}"; done
				for value in "${FictionResponseCookie[@]}"; do printf 'Set-Cookie: %s\n' "$value"; done
				(( ! empty_body )) && printf "\n"
			fi
			(( size == 0 || empty_body )) || cat "$filename"
		} >"$WORKER_FIFO"
	fi
	#printf "\n"
	#exec 1>&4 4>&-
	#exec 3>&-
	rm "$filename"
	time_ms
	local time2="$ms"

	local time=$((time2-worker_init_time))
	if ((time < 150)); then
		time="${_green}${time}${_nc}ms"
	elif ((time < 500)); then 
		time="${_yellow}${time}${_nc}ms"
	else
		((time > 1000)) && printf -v time "${_red}%.2f${_nc}s" "${time}e-3" || time="${_red}${time}${_nc}ms"
	fi
	if ((size > 1048576)); then
		builtin printf -v size "%.2f MB" "$((size/1024))e-3"
	elif ((size > 1024)); then
		builtin printf -v size "%.2f KB" "${size}e-3"
	else 
		size="$size B"
	fi
	case "${FictionResponse[status]::3}" in
		2[0-9][0-9]) local status="${_green}${FictionResponse[status]}${_nc}" ;;
		3[0-9][0-9]) local status="${_yellow}${FictionResponse[status]}${_nc}" ;;
		4[0-9][0-9]|5[0-9][0-9]) local status="${_red}${FictionResponse[status]}${_nc}" ;;
		*) status="${FictionResponse[status]}"
	esac
	builtin printf -v timestamp "%(%d/%m/%y %H:%M:%S)T"
	if [[ ${FICTION_MODE} == development ]]; then
		cat << EOF >&2
${_gray}${timestamp}${_nc} ${FictionRequest[version]} ${FictionRequest[method]} ${FictionRequest[path]} $status in $time ($size)
Handled by: $handled_by
EOF
		[[ "${Fiction[logs.show_addr]:=true}" == true ]] && printf "%s\n" "Address: ${FictionRequestHeaders[x-forwarded-for]:=${FictionRequest[addr]}}"

		if [[ "${Fiction[logs.show_headers]:=false}" == true ]]; then
			printf "%s\n" "Headers: "
			for key in ${!FictionRequestHeaders[@]}; do 
				printf "%s\n" "${_bold}$key:${_nc} ${FictionRequestHeaders[$key]}"
			done
		elif "${Fiction[logs.show_ua]:=false}"; then
				printf "%s\n" "Headers: "
		fi
	else
			printf "%s" "${_gray}${timestamp}${_nc} "
			"${Fiction[logs.show_addr]:=false}" && printf "%s" "${FictionRequestHeaders[x-forwarded-for]:-${FictionRequest[addr]}}"
			printf "%s\n" " ${FictionRequest[method]} ${FictionRequest[path]} $status $time"
	fi
	unset status handled_by routetype size time
	#exit
}

function fiction.addMeta() {
	local input
	[[ "$#" == 0 ]] && read -rd'' input || input="$@"
	FictionResponse[head]+="$input"
}

function fiction.header.set() {
	[[ -z "$1" || -z "$2" ]] && return
	FictionResponseHeaders["$1"]="$2"
}

function fiction.cookie.set() {
	FictionResponseCookie+=("$1")
}

fiction.respond() {
	local output;
		[[ "$__fiction_responded" == 1 ]] && return
		[[ -z "$1" ]] && _error "At least one argument expected" >&2 && return 1
		fiction.response_code.set "$1"
		[[ $1 != 204 && -z "$2" ]] && while read -rd'' chunk; do output+="$chunk"; done || local output="$2"
		echo "$output" >"$WORKER_OUT"
		__fiction_responded=1
	return
}

declare -F fiction.404 >/dev/null || fiction.404() {
#  INCLUDE_DOM=false
#  Fiction[include_lucide]=false
	FictionResponseHeaders=(['content-type']="text/html")
	handled_by="fiction.404"
	fiction.respond 404 <<- EOF
	<!DOCTYPE html>
	<html style="font-family: ui-sans-serif, system-ui, sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Noto Color Emoji';background-color:black;color:white;">
		<meta>
			<title>Not found - Fiction</title>
		</meta>
		<body>
			<div style="text-align: center;">
				<h1 style="font-weight: bold; font-size:48px; margin-bottom: 10px;">404 | Not Found</h1>
				The route is... fictional?
			</div>
		</body>
	</html>
EOF
	return
}

declare -F fiction.500 >/dev/null || fiction.500() {
	handled_by="fiction.500"
	FictionResponseHeaders=(['content-type']="text/html")
	fiction.respond 500 <<- EOF
	<!DOCTYPE html>
	<html style="font-family: ui-sans-serif, system-ui, sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Noto Color Emoji';background-color:black;color:white;">
		<meta>
			<title>Server error - Fiction</title>
		</meta>
		<body>
				<div style="text-align: center;">
				<h1 style="font-weight: bold; font-size:48px; margin-bottom: 10px;">500 | Server Error</h1>
				You got us! We couldn't process your request properly
			</div>
			<div>
		</body>
	</html>
EOF
	return
}

function fiction() {
	echo "fiction.server ${Fiction[version]}"
	printf "%s" "running as: "
	(( is_sourced )) && printf "%s (called from: %s)\n" "module" "${BASH_SOURCE[-1]}" || printf "%s (path: %s)\n" "standalone" "${FICTION_PATH}/fiction.so.sh"
	echo "PID: $$"
	echo "mode: ${FICTION_MODE}"
	echo "hot reload: ${Fiction[hot_reload.enabled]}"
	echo "loaded modules:" 
	for key in ${!FictionModule[@]}; do
		echo "  $key: ${FictionModule[$key]}"
	done
	#echo "Available functions:"
	#local var=$(declare -F | sed -n -e '/fiction/ { /\./ p; }')
	#echo "${var//declare -f/ }"

}


function fiction.serve() {
	# fiction.serve <from> <to:fn> <as> <type?> <headers?>
	local funcname route args
	[[ "$FICTION_HOTRELOAD" ]] && return
	[[ -z "$1" || -z "$2" ]] && _error "\$1 or \$2 missing" && return 1
	local type="${4:-static}"
	[[ "${FictionRoute["$1"]}" ]] && _error "Dublicate of existing route $1" && return 1
	route="$1"
	[[ "${route: -1}" == '/' ]] || route="${route}/"
	read -r funcname args <<< "$2"
	case "$type" in 
		"cgi")
			if [ ! -x "$2" ]; then 
				_error "$2 is not an executable. Check if the file exists and has executable permission"
				return 1
			fi
			FictionRoute["$route"]="$route|$funcname|cgi|${3:-auto}"
			;;
		"static"|"file")
			if ! declare -F "$funcname" > /dev/null; then 
				_error "$funcname is not a function"
				return 1
			fi
			FictionRoute["$route"]="$route|${funcname}${args:+ $args}|$type|${3:-auto}"
			;;
		"dynamic")
			if ! declare -F "$funcname" > /dev/null; then 
				_error "$funcname is not a function"
				return 1
			fi
			FictionDynamicRoute+=("$route|${funcname}${args:+ $args}|$type|${3:-auto}")
			;;
		*)
			_error "Invalid route type: $type"
			return 1
	esac
	#FictionRoute["$route"]="$route|$funcname${args:+ $args}|$type|${3:-auto}"
	#if [ ! -f "$serverTmpDir/.routes" ]; then
	#	echo "$route|$funcname${args:+ $args}|$type|${3:-auto}" >"$serverTmpDir/.routes"
	#else
	#	echo "$route|$funcname${args:+ $args}|$type|${3:-auto}" >> "$serverTmpDir/.routes"
	#fi
	"${FICTION_BUILD:-false}" || echo "[${_white}+${_nc}] Added ${type} route: from ${_bold}'$1'${_nc} to ${_bold}'$funcname'${_nc} ${3:+as '$3'}"
}

function fiction.serveDynamic() {
	# fiction.serveDynamic <from> <to:fn> <as>
	[[ -z "$1" || -z "$2" ]] && return 1
	fiction.serve "$1" "$2" "$3" dynamic
}

function fiction.serveCGI() {
	fiction.serve "${2:-/${1//.\/}}" "$1" "$3" cgi
}

function fiction.redirect() {
	[[ -z "$1" ]] && _error "Expected \$1, but got null" && fiction.500 && return
	fiction.header.set "server" "Fiction/${Fiction[version]}"
	fiction.header.set "location" "$1"
	fiction.respond 301
}

function fiction.serveFile() {
	[ ! -f "$1" ] && _error "$1 is not a file" && return 1
	subshell uuid uuidgen
	local ROUTEFN="FR${uuid}";
	unset uuid
	if [[ "$4" ]]; then
		declare -n __headers="$4"
		local hline='';
		for header in ${!__headers[@]}; do
		hline+=" fiction.header.set '$header' '${__headers[$header]}'; ";
		done
		unset headers
	fi
	eval "${ROUTEFN}(){ ${4:+$hline} cat \"$1\"; }";
	local ROUTEPATH;
	if [[ -n "$2" ]]; then
		ROUTEPATH="$2";
	else
		ROUTEPATH="${1}";
		if [ "${ROUTEPATH::1}" == "." ]; then
			ROUTEPATH="${ROUTEPATH:1}";
		fi
		if [[ "${ROUTEPATH::1}" != '/' ]]; then
			ROUTEPATH="/${ROUTEPATH}";
		fi
	fi
	fiction.serve "${ROUTEPATH}" "${ROUTEFN}" "${3:-$(file --mime-type -b "${1}")}" "file"
}

function fiction.serveDir() {
	local ROUTE_APPEND="$2";
	local download="$3";
	[[ "${download:-true}" == true ]] && local type=application/x-octet-stream;
	if [[ -n "$ROUTE_APPEND" ]] && [[ "${ROUTE_APPEND: -1}" == "/" ]]; then
		ROUTE_APPEND="${ROUTE_APPEND:0:0-1}";
	fi
	if [ -d "$1" ]; then
		
		if [[ "${4:-true}" == true ]]; then
			subshell fullpath readlink -f $1
			fiction.serve "${ROUTE_APPEND}" "tree -H \"$ROUTE_APPEND\" -L 1 '$fullpath'" "text/html";
			unset fullpath
		fi
		test -e "$1/"* > /dev/null 2>&1 && for item in ${1}/*;
		do
			if [ -d "$item" ]; then
				[[ "${5:-true}" == true ]] && fiction.serveDir "${item}" "${ROUTE_APPEND}/${item##*/}" "$download" > /dev/null;
			else
				ROUTEPATH="${item}"
				if [ "${ROUTEPATH::1}" == "." ]; then
					ROUTEPATH="${ROUTEPATH:1}";
				fi
				fiction.serveFile "${item}" "${ROUTE_APPEND}/${ROUTEPATH##*/}" "$type" > /dev/null;
			fi
		done
	else
		_error "$1 is not a directory"
		return 1;
	fi
}


function fiction.server() {
	[[ "$FICTION_BUILD" || "$FICTION_HOTRELOAD" ]] && return

	local address="${Fiction[address]}" port="${Fiction[port]}"
	if [[ -s "$FICTION_PATH/fiction.lock" ]]; then
		_read_file pid "$FICTION_PATH/fiction.lock"
		if [[ -f "/proc/$pid/status" ]]; then
			_error "failed to acquire lock file. it is held by another instance ($pid)"
			return
		else
			echo "$$" > "$FICTION_PATH/fiction.lock"
		fi
	else
		echo "$$" > "$FICTION_PATH/fiction.lock"
	fi

	if timeout 0.1 bash -c "</dev/tcp/$address/$port &>/dev/null" 2>/dev/null; then
		_error "cannot bind on $address:$port: Address already in use"
		return 1
	fi

	[[ "$FICTION_SERVER" ]] && { _error "another instance of fiction.server is already running"; return 1; }
	FICTION_SERVER=true
	[[ -v FICTION_MODE ]] || FICTION_MODE="production"
	#if [[ -z "${FictionRoute['/favicon.ico']}" && -f "${FICTION_PATH}favicon.ico" ]]; then 
	#	declare -A _hh=([cache-control]="public,max-age=86400" [age]=0)
	#	fiction.serveFile "${FICTION_PATH}favicon.ico" "/favicon.ico" "" "_hh" >/dev/null
	#
	#fi
	printf "\n%s\n" "Fiction (${_green}${Fiction[version]}${_nc})"
	#set -x
	#[[ "${Fiction[include_wasm]}" == true && "${Fiction[ssl.enabled]:=false}" == false ]] && _error "Running the website with WASM included on HTTP. Modern browsers will not allow WASM initialization from HTTP origin. In case it's a development server, consider using ncat for running a temporary HTTPS server." && return 1
	trap clean EXIT INT;
	case "${Fiction[core]}" in
		bash)
			echo -n "Server address: ";
			[[ "$port" = 80 ]] && \
					echo -n "http://$address" || \
					echo -n "http://$address:$port";
			echo " (${FICTION_MODE:-${FICTION_MODE}} mode)";
			trap catch_job SIGCHLD
			echo 0 > "$serverTmpDir/.conns"
			_spawn 'network listener'
			time_ms
			local time2="$ms"
			echo "Ready in $((time2-init_time))ms"
			_console
		;;
		nc | netcat | ncat | socat)
			_buildWorker
			echo -n "Server address: ";
			if "${Fiction[ssl.enabled]:=false}"; then
				[[ "$port" = 443 ]] && \
					echo -n "https://$address" || \
					echo -n "https://$address:$port";
			else
				[[ "$port" = 80 ]] && \
					echo -n "http://$address" || \
					echo -n "http://$address:$port";
			fi
			echo " (${FICTION_MODE:-${FICTION_MODE}} mode)";
			trap catch_job SIGCHLD
			echo 0 > "$serverTmpDir/.conns"
			_spawn 'network listener'
			mkfifo "$serverTmpDir/.workers"
			_spawn 'threader'
			time_ms
			local time2="$ms"
			echo "Ready in $((time2-init_time))ms"

			#if [[ ${FICTION_MODE} == development || ${Fiction[hot_reload.enabled]} = true ]]; then 
			#	_spawn 'hot-reload'
			#fi
			_console
		;;
		*)
			_error "Invalid core: ${Fiction[core]}"
			exit 1
	esac
}



_hotreload() {
	FICTION_HOTRELOAD=true
	FICTION_NESTED=true
	local __files=()
	local hl_file file
	for file in ${Fiction[hot_reload.files@v]//\'}; do
		#local _value="${Fiction[hot_reload.files.$file]}"
		local _value="$file"
		[[ "${_value::1}" != '/' ]] && _value="${FICTION_PATH}${_value}"
		[[ "$_value" == *' '* ]] && __files+=("'$_value'") || __files+=("$_value")
	done

	_warn "Hot-Reload enabled. This is an experimental feature, use it with caution."

	if which inotifywait >/dev/null 2>&1; then
		i=0
		inotifywait -qm --event modify --format '%w' ${__files[@]} | while read -r hl_file; do
			((i == 1)) && i=0 && continue  
			if [[ ! "$hl_file" =~ \.shx|\.bashx ]]; then 
				source "$hl_file" __hotreload && printf "%s\n" "[$_green✓$_nc] Reloaded $hl_file" || printf "%s\n" "[${_red}x${_nc}] Failed to reload $hl_file"
			else
				BASHX_VERBOSE=true @import "$hl_file"; 
			fi
		done
	else
		_warn "inotify-tools package is not installed, Hot-Reload will use md5sum to compare files every ${Fiction[hot_reload.interval]:=2}s"
		local -A _hl_files=()
		for hl_file in "${__files[@]}"; do
			subshell _var md5sum "$hl_file"
			_hl_files["$hl_file"]="$_var";
			unset _var
		done

		while sleep ${Fiction[hot_reload.interval]}; do
			for hl_file in "${__files[@]}"; do
				subshell hl_file2 md5sum "$hl_file"
				[[ "$hl_file2" == "${_hl_files["$hl_file"]}" ]] && continue
				printf "%s\n" "(hot-reload) Reloading $hl_file..."
				if [[ ! "$hl_file" =~ \.shx|\.bashx ]]; then
					source "$hl_file" __hotreload && printf "%s\n" "[$_green✓$_nc] Reloaded $hl_file" || printf "%s\n" "[${_red}x${_nc}] Failed to reload $hl_file"
				else
					BASHX_VERBOSE=true @import "$hl_file"; 
				fi
				#[[ ${Fiction[core]} != bash ]] && _buildWorker
				_hl_files["$hl_file"]="$hl_file2";
			done
		done
	fi
}


_build() {
	echo "Initializing build..."
	time_ms
	local time="$ms"
	FICTION_MODE=build
	[[ "$2" ]] && Fiction[default_index]="$2"
	[[ "$3" ]] && target_dir="$3"
	BASHX_VERBOSE=true
	FICTION_NESTED=true
	FICTION_BUILD=true
	for file in "${FICTION_PATH}"pages/*; do
		if [[ "$file" == *.shx ]]; then 
			[[ -v FictionModule[bashx] ]] && bashx "$file" || { _error "cannot load bashx file without bashx module"; exit 1; }
		else
			source "$file"
		fi
	done
	[[ $? > 0 ]] && exit
	for route in "${FictionRoute[@]}"; do
		# FictionRoute["$route"]="$route|${funcname}${args:+ $args}|$type|${filetype:-auto}"
		IFS='|' read route func type filetype <<< "$route";
		echo -ne "(-) $route...\r"
		if [[ "$type" == "file" ]]; then
			path="${default_dir:=fiction_compiled}${route}"
			mkdir -p "${path%/*}"
			"$func" > "$path"
			echo "[$_green✓$_nc] $route ($path)"
			continue
		fi
		path="${default_dir:=fiction_compiled}$route"
		[[ "$route" ]] && mkdir -p "$path"
		read func funcargs <<< "$func";
		WORKER_OUT="$path/$type.html"
		${func} ${funcargs//\"/\\\"} & 
		pid=$!
		s='-\|/'; i=0; while kill -0 $pid 2>/dev/null; do i=$(((i+1)%4)); printf "\r[${s:$i:1}] $route\r"; sleep .1; done
		wait $pid
		if [[ "$filetype" == text/html && "$type" != cgi ]]; then
			__htmlhelper "$path/$type.html";
		fi
		exit=$?
		[[ $exit == 0 ]] && [ -f "$path/$type.html" ] && echo "[$_green✓$_nc] $route (${path%%\/}/${type}.html)" ||  echo "[${_red}x${_nc}] $route ($exit)"
	done
	rm -rf "$serverTmpDir"
	time_ms
	echo "Build completed. ($((ms-time))ms)"
}

_buildWorker() {
		#echo "FICTION_PATH='$FICTION_PATH'"
		#declare -f subshell
		#declare -A
		#unset -f fiction.server @cache @prerender  _modulesLoader _hotreload _configParser _build _buildWorker _helpmsg
		#unset -f json_pretty
		#[[ "${FictionModule[bashx]}" ]] && unset -f @import bashx _mktmpDir @render_type @wrapper _render _conditionalRender
		#[[ "${FictionModule[mdx]}" ]] && unset -f __renderMd
		#current_snapshot="$(set)"
		#current_snapshot="${current_snapshot//$'\n'/; }"
		#echo "${current_snapshot//${env_snapshot//$'\n'/; }}"
		#declare -p $(compgen -v | grep -v -F -f <(env -i bash -c 'compgen -v; printf "%s\n" BROWSER PS1 PS2 HISTFILE HOME LINES MAILCHECK COLUMNS HISTSIZE LANG LOGNAME PIPESTATUS USER envVarsToReport BASH_ALIASES BASH_CMDS'))
		#declare -f
		#declare | \
		#	grep -vE '(^DBUS_SESSION_BUS_ADDRESS|^WAYLAND_|^FUNCNAME|^LANG|^ICEAUTHORITY*|^MEMORY_PRESSURE*|^LS_COLORS*|^HOST*|^WASMER*|^Fiction.*=|^chunk=|^newblock=|^out1=|^GPG|^SHELL|^SESSION_|^OS|^KDE_*|^GTK*|^XDG*|^XKB*|^PAM*|^KONSOLE*|^SSH_*|^QT_*|^PWD|^OLDPWD|^TERM|^HOME|^USER|^PATH|^BASH_*|^BASHOPTS|^EUID|^PPID|^SHELLOPTS|^UID)'
		[[ -z "$1" ]] && cat <<EOF  >"$serverTmpDir/worker.sh";
#!/bin/bash
HEADERS=""
trap 'rm "/dev/shm/.worker-\$uuid.in" "/dev/shm/.worker-\$uuid.out" "/dev/shm/.fiction_buf_\$uuid" 2>/dev/null' INT EXIT
read uuid < /proc/sys/kernel/random/uuid
read conns < "$serverTmpDir/.conns" 2>/dev/null
#declare -f >&2
HEADERS=""
mkfifo "/dev/shm/.worker-\$uuid.in"
mkfifo "/dev/shm/.worker-\$uuid.out"
while read -r val; do
	val="\${val//$'\r'/}"
	HEADERS+="\$val"$'\n'
	[[ "\${val,,}" =~ 'content-length' ]] && IFS=':' read key value <<< "\${val,,}"
	[[ "\${#val}" < 1 ]] && break
done
[[ "\${value// }" -gt 1 ]] && { read -rn \${value// } -t1 data; [[ \${#data} > 1 ]] && HEADERS+="\${data//$'\r'/}"$'\n'; unset key value data; }
[[ "\$NCAT_REMOTE_ADDR" ]] && REMOTE_ADDR="\$NCAT_REMOTE_ADDR" || REMOTE_ADDR="\$FICTION_PEERADDR"
$([[ "$workerargs" ]] && echo 'set $workerargs')
echo "\$uuid;\$REMOTE_ADDR" > $serverTmpDir/.workers
echo "\$HEADERS" > "/dev/shm/.worker-\$uuid.out"

cat "/dev/shm/.worker-\$uuid.in"
case "\$conns" in
	0) echo 1 > "$serverTmpDir/.conns" ;;
	*) echo "\$((conns + 1))" > "$serverTmpDir/.conns" ;;
esac

EOF
	chmod +x "$serverTmpDir/worker.sh";
}

_modulesLoader() {
	[[ "$1" ]] && local modules=("$@") || local modules=($FICTION_PATH/modules/*)
	local dir
	for dir in "${modules[@]}"; do
		case "${dir##*/}" in
			accept)
				[[ -v __modules[accept] ]] && continue
				FictionModule[accept]="$dir"
			;;
			test_ui)
				[[ -v __modules[ui] ]] && continue
				if [[ -f "$dir/index.sh" ]]; then
					FictionModule[ui]="$dir"
					source "$dir/index.sh"
				else 
					_error "cannot find UI module ($dir/index.sh)"
				fi
			;;
			bashx)
				[[ -v FictionModule[bashx] ]] && continue
				if [[ -f "$dir/bashx" ]]; then
					FictionModule[bashx]="$dir/bashx"
					[[ "${FICTION_MODE}" == development ]] && BASHX_VERBOSE=true
					BASHX_NESTED=true 
					source "$dir/bashx"
				else
					_error "cannot find bashx ($dir/bashx)"
				fi
			;;
			bash-wasm)
				[[ -v FictionModule[wasm] ]] && continue
				if [[ -f "$dir/index.sh" ]]; then
					FictionModule[wasm]="$dir"
					source "$dir/index.sh"
				else
					_error "cannot find WASM module ($dir/index.sh)"
				fi
			;;
			shelljq)
				[[ -v FictionModule[shelljq] ]] && continue
				if [[ -f "$dir/index.sh" ]]; then
					FictionModule[shelljq]="$dir"
					source "$dir/index.sh"
				else
					_error "cannot find WASM module ($dir/index.sh)"
				fi
			;;
			*) 
				_warn "External module: ${dir##*/}. Trying to load index.sh by default"
				if [[ -f "$dir/index.sh" ]]; then
					FictionModule["${dir##*/}"]="$dir"
					source "$dir/index.sh"
				else
					_error "cannot find $dir/index.sh; ignoring"
				fi
			;;
		esac
	done
}

_pluginsLoader() {
	for plugin in ${Fiction[plugins@v]//\'}; do
			case "$plugin" in
				"tailwindcss") FictionResponse[head]+='<script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>' ;;
				"lucide-icons") FictionResponse[head]+='<script src="https://unpkg.com/lucide@latest"></script>' ;;
				"dom") subshell _dom_contents cat "$dom_path"; FictionResponse[head]+="<script>${_dom_contents}</script>" ;;
			esac
	done
}

_configParser() {
	[[ -v FictionModule[shelljq] ]] || { _error "shelljq module is not loaded, cannot proceed"; exit 1; }
	if [[ ! -f "$FICTION_PATH/config.json" || ! -s "$FICTION_PATH/config.json" ]]; then
		_error "$FICTION_PATH/config.json is not found or empty"
		exit 1
	else
		local config
		_read_file config "$FICTION_PATH/config.json"
		json_trim "$config" true true
		[[ $? > 0 ]] && _error "failed to validate the configuration" && exit 1
	fi
	json_to_arr "$json_trim_output" Fiction "" "" "" true
	unset json_trim_output
	Fiction[default_index]="${FICTION_PATH}pages/${Fiction[default_index]:=index.shx}"
	readonly -A Fiction
	set -x
	#[[ "${Fiction[allowed_hostnames]}" != '[]' ]] && declare -gra __allowed_hostnames=(${Fiction["allowed_hostnames@v"]}) || declare -gra __allowed_hostnames=()
	set +x
}

_helpmsg() {
	cat << EOF
Usage: $0 [action] [arguments]

Available actions:
	run   [file?]           Start the production server using <file> (pages/index.shx default)
	dev   [file?]           Start the development server using <file> (pages/index.shx default)
	build [file?] [target?] Build the routes defined in <file> into <target> directory (fiction_compiled default)
	version                 Return server version
	help                    Show this message
EOF
}

#_modulesLoader /home/tirito/fiction/framework/modules/shelljq
#_configParser
#exit
if ! (return 0 2>/dev/null); then
	case "$1" in
	run|dev)
		_mktmpDir
		time_ms
		_modulesLoader
		[[ "$1" == dev ]] && FICTION_MODE=development || FICTION_MODE=production
		[[ "$2" ]] && Fiction[default_index]="$2"
		_configParser
		_pluginsLoader
		BASHX_VERBOSE=true
		FICTION_NESTED=true
		for file in "${FICTION_PATH}"pages/*; do
			if [[ "$file" == *.shx ]]; then 
				[[ -v FictionModule[bashx] ]] && bashx "$file" || { _error "cannot load bashx file without bashx module"; exit 1; }
			elif [[ "$file" == *.sh ]]; then
				source "$file"
			fi
		done
		fiction.server
	;;
	build) 
		_modulesLoader
		_configParser
		_pluginsLoader
	 	_build && exit ;;
	version)
		cat <<- EOF
			Fiction ${Fiction[version]}
			Copyright (C) Tirito6626, notnulldaemon 2025-2026
EOF
	;;
	help) _helpmsg ;;
	*)
		_error "Invalid action: $1"
		_helpmsg >&2
		exit 1
	;;
	esac
else
	_mktmpDir
	[[ "$FICTION_HOTRELOAD" ]] || _modulesLoader
	_configParser
	if [[ "$FICTION_NESTED" != true ]]; then
		if [[ "${FICTION_MODE}" == build ]]; then 
			_build
			exit
		fi
		if [[ "${BASH_SOURCE[-1]}" =~ .shx|.bashx ]]; then
				FICTION_NESTED=true
				bashx "${BASH_SOURCE[-1]}"
				exit
		fi
	fi
fi
