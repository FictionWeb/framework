#!/bin/bash
# The Fiction(R) Library, powered by insane people
FICTION_PATH=$(readlink -f "${BASH_SOURCE[0]:-$0}")
FICTION_PATH="${FICTION_PATH//fiction.so.sh}"
[[ -v FICTION_META ]] || FICTION_META=""
_green=$'\e[38;5;2m'
_red=$'\e[38;5;1m'
_yellow=$'\e[38;5;3m'
_white=$'\e[38;5;255m'
_bold=$'\e[1m'
_gray=$'\e[38;5;240m'
_nc=$'\e[0m'
[[ "$FICTION_NESTED" == true ]] && return
# Main configuration object. It contains all options, paths, routes, arguments and modules
declare -gA Fiction=(
  [version]="v1.0.0-prerelease" # Server's version
  [path]="${FICTION_PATH}" # Fiction's absolute path
  # Pointers to child arrays. If pointers use custom value, Fiction* variables will reference custom values
  [routes]=FictionRoute 
  [modules]=FictionModule
  [response]=FictionResponse 
  [request]=FictionRequest
)

#workerargs="-x"
declare -gA FictionRoute
declare -gA FictionResponse=(
  [status]=""
  [headers]=FictionResponseHeaders
  [cookie]=FictionResponseCookie
  [head]="$FICTION_META" 
)

declare -gA FictionRequest=(
  [headers]=FictionRequestHeaders
  [cookies]=FictionRequestCookie
  [query]=FictionRequestQuery
  [data]=FictionRequestData
)
declare -gA FictionRequestHeaders FictionRequestQuery FictionRequestData FictionRequestCookie FictionResponseHeaders FictionResponseCookie
declare -gA FictionModule=( 
  # Example on adding module: 
  # FictionModule[bashx]="${Fiction[path]}/modules/bashx/bashx"
)

declare -a __funcs;

# Code structure
# - subshell
# - _hash
# - _encode
# - _decode
# - _regex
# - @cache
# - @prerender
# - mktmpDir
# - error
# - warn
# - json_list
# - json_to_arr
# - urldecode 
# - uuidgen
# - httpSendStatus
# - __e
# - __d
# - generate_csrf_token
# - generate_session_id
# - rename_fn
# - parsePost
# - fiction.router
# - fiction.processHTTP
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
# - clean
# - declare_objects

# Helper functions
function subshell() {
  local var="$1"
  #printf -v "$var" "$(${@:2})"
#  return
  ${@:2} >"/dev/shm/.fiction_out"
  read -r -d $'\0' $var <"/dev/shm/.fiction_out"
}

function _read_file() {
  read -r -d $'\0' "$1" <"$2"
}

subshell _green tput setaf 2

function _hash() {
  sha256sum <<< "$1"
}

function _encode() {
  base64 -w 0 <<< "$1"
}

function _decode() {
  base64 -d <<< "$1"
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
  declare -F "$1" >/dev/null && return
 # @cache "$1" # just in case
  local PRERENDER_DATA="$1(){ echo \"$(eval "$1" | sed 's+"+\\"+g')\"; }"
  eval "$PRERENDER_DATA"
  if declare -F "$1" >/dev/null; then
  PRERENDER_DATA="\\$1(){ echo \"$(eval "\\$1" | sed -e 's+"+\\"+g')\"; }"
  eval "$PRERENDER_DATA"
  fi
}

function mktmpDir() {
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

# ---- bash2json integration ----
json_list() {
local input="${1# }"
local sub="$2"
local depth=0 result='' quoted=0 escaped=false
if [[ "${input:0:1}" = '{' ]]; then
  while IFS='' read -r -d '' -n 1 char; do
    [[ "$quoted" = 0 && "$char" == " " ]] && continue
    [[ "$prevchar" == '\' ]] && escaped=true && continue
     if "$escaped"; then
      escaped=false
    elif ((quoted != 0)); then
      [[ "$char" == '"' ]] && ((quoted ^= 1))
    else
    if (( depth == 1 )); then
      case "$char" in
      ':') result+=" " && continue ;;
      ',') result+=$'\n' && continue ;;
      esac
    fi
      case "$char" in
      '"') ((quoted ^= 1)) ;;
      '{'|'[') ((++depth)); ((depth == 1)) && continue ;;
      '}'|']') ((--depth)); ((depth == 0)) && continue ;;
      esac
    fi
    result+="$char"
    ((depth == 0)) && break
  done <<<"$input"
  json_list_output="$result"
elif [[ "${input:0:1}" = '[' ]]; then
  while IFS='' read -r -d '' -n 1 char; do
    [[ "$quoted" = 0 && "$char" == " " ]] && continue
    [[ "$prevchar" == '\' ]] && escaped=true && continue
    if "$escaped"; then
    escaped=false
    elif ((quoted != 0)); then
    [[ "$char" == '"' ]] && ((quoted ^= 1))
    else
      case "$char" in
      '"') ((quoted ^= 1)) ;;
      '\') escaped=true ;;
      ',') result+=$'\n' && continue ;;
      '[') ((++depth)); ((depth == 1)) && continue ;;
      ']')  ((--depth)); ((depth == 0)) && break ;;
      '{') ((++depth)) ;;
      '}') ((--depth)) ;;
      esac
    fi
    result+="$char"
    ((depth == 0)) && break
  done <<<"$input"
  json_list_output="$result"
else
  json_list_output="$input"
fi
! "${sub:=false}" && echo "$json_list_output"
}

json_to_arr() {
  local sub="$4"
  local json="${1# }"
  local result=''
  [ -z "$2" ] && local output_arr=array_$RANDOM || local output_arr="$2"
  json_list "$json" true
  mapfile  -t json_to_arr_array < <(printf '%b' "${json_list_output}")
  if [[ "${json:0:1}" == '{' ]]; then
    [ -z "$3" ] && result+="declare -Ag $output_arr=(" || local parentkey="${3//\"}."
    for line in "${json_to_arr_array[@]}"; do
    IFS=' ' read key value <<< "$line"
    [ -z "$key" ] && continue || key="${key//\"}"
    if [[ ${value:0:1} == "{" ]]; then
      $FUNCNAME "$value" "" "${parentkey}${key}" true
      result+="$json_to_arr_output"
    else
      [[ "${value: -1}" == '"' ]] && result+="[${parentkey}${key}]=$value " || result+="[${parentkey}${key}]='$value' "
    fi
    done
  elif [[ "${json:0:1}" == '[' ]]; then
    [ -z "$3" ] && result+="declare -ag $output_arr=("
    for key in "${json_to_arr_array[@]}"; do
    key="${key#\"}"
    result+="'${key%\"}' "
    done <<< "$json_list_output"
  fi
  [ -z "$3" ] && result+=')'
  json_to_arr_output="${result/% \)/)}"
  ! "${sub:=false}" && echo "$json_to_arr_output"
  return 0
}

# --- end of bash2json ----

# https://github.com/dylanaraps/pure-bash-bible#decode-a-percent-encoded-string
urldecode() {
  : "${1//+/ }"
  printf '%b\n' "${_//%/\\x}"
}

# https://gist.github.com/markusfisch/6110640
uuidgen() {
  cat /proc/sys/kernel/random/uuid
}

httpSendStatus() {
  local -A status_code=(
  [101]="101 Switching Protocols"
  [200]="200 OK"
  [201]="201 Created"
  [301]="301 Moved Permanently"
  [302]="302 Found"
  [400]="400 Bad Request"
  [401]="401 Unauthorized"
  [403]="403 Forbidden"
  [404]="404 Not Found"
  [405]="405 Method Not Allowed"
  [418]="I'm a teapot"
  [429]="Too many requests"
  [500]="500 Internal Server Error"
  [503]="Bad gateway"
  )

  FictionResponse["status"]="${status_code[${1:-200}]}"
}
subshell key1 openssl rand -hex 32
subshell key2 openssl rand -hex 16
__x4gT9q6=( "$key1" "$key2" );
unset key1 key2

__e() {
  "${Fiction[encode_routes]}" && openssl enc -aes-256-cbc -K "${__x4gT9q6[0]}" -iv "${__x4gT9q6[1]}" -out "$2" <<< "$1" || echo "$1" > "$2"
}

__d() {
  "${Fiction[encode_routes]}" && openssl enc -d -aes-256-cbc -K "${__x4gT9q6[0]}" -iv "${__x4gT9q6[1]}" -in "$1" || cat "$1"
}


function generate_csrf_token() {
  openssl rand -base64 48
}

function generate_session_id() {
  openssl rand -hex 48
}

rename_fn() {
  local a
  a="$(declare -f "$1")" &&
  eval "function $2 ${a#*"()"}"
  unset -f "$1";
}

function fiction.router() {
  [[ "${FictionRequest[path]}" =~ ".."|"~" ]] && handled_by="fiction.404" && fiction.404
  [ "${FictionRequest[path]::2}" == "//" ] && FictionRequest[path]="${FictionRequest[path]:1}";
  [ "${FictionRequest[path]::1}" != "/" ] && FictionRequest[path]="/${FictionRequest[path]}";
  [[ "${FictionRequest[method]}" == 'POST' && -n "${FictionRequestHeaders['fiction-action']}" ]] && FictionRequest[path]="/${FictionRequestHeaders['fiction-action']}";
  if [ -f "$serverTmpDir/.routes" ]; then
    local route func route1 func1 m=false ou;
    subshell routes __d "$serverTmpDir/.routes";
    subshell ou grep "${FictionRequest[path]}" <<< "$routes"
    subshell ou2 grep "dynamic" <<< "$routes"
    if [[ "$ou" ]]; then
      read type filetype route func <<< "$ou";
      read func funcargs <<< "$func";
      FICTION_ROUTE="${FictionRequest[path]}";
      handled_by="$func"
      if [[ $type == cgi ]]; then
        local headers=;
        (
        SERVER_SOFTWARE="fiction/${Fiction[version]//v}" \
        REQUEST_METHOD="${FictionRequest[method]}" \
        REMOTE_ADDR="$REMOTE_ADDR" \
        FICTION_ROUTE="${FictionRequest[path]}" \
        FictionRequest[path]="${FictionRequest[path]}" \
        CONTENT_LENGTH="${FictionRequestHeaders[content-length]}" \
        SCRIPT_NAME="$func" \
        HTTPS="${Fiction[ssl.enabled]}" \
        SCRIPT_FILENAME="$func" \
        HTTP_USER_AGENT="${FictionRequestHeaders[user-agent]}" \
        HTTP_COOKIE="${FictionRequestHeaders[cookie]}" \
        $func;
        )
      else
        #parsePost
        [[ "$func" == 'echo' ]] && $func "${funcargs//\"/\\\"}" || $func ${funcargs};
      fi
    else
      if [[ -n "$ou2" ]]; then
        while read route; do
          read type contenttype route func <<< "$route"
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
        done <<< "$ou2"
        fiction.404
      else
        fiction.404;
      fi
    fi
  else
    fiction.404;
  fi
}

function fiction.processHTTP() {
  subshell time1 date +%s%3N
  local REQUEST_METHOD REQUEST_PATH HTTP_VERSION entry key value
  read -r REQUEST_METHOD REQUEST_PATH HTTP_VERSION
  HTTP_VERSION="${HTTP_VERSION%%$'\r'}"
  [[ "$HTTP_VERSION" =~ HTTP/[0-9]\.?[0-9]? ]] && HTTP_VERSION="${BASH_REMATCH[0]}" || return
  [[ -z "$REQUEST_METHOD" || -z "$REQUEST_PATH" ]] && return
  FictionRequest=(
    [method]="$REQUEST_METHOD"
    [path]="$REQUEST_PATH"
    [version]="$HTTP_VERSION"
    [addr]="$REMOTE_ADDR"
    [headers]="FictionRequestHeaders"
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
  IFS='&' read -ra data <<<"$get"
  if [[ ${#data[@]} > 0 ]]; then
    FictionRequest[query]="FictionRequestQuery"
    for entry in "${data[@]}"; do
      FictionRequestQuery["${entry%%=*}"]="${entry#*=}"
    done
  fi

  if [ -n "${FictionRequestHeaders["Cookie"]}" ]; then
    IFS=';' read -ra cookie <<<"${FictionRequestHeaders["cookie"]}"
    FictionRequest[cookie]="FictionRequestCookie"
    ((${#cookie[@]} < 1 )) 
    cookie+=( ${FictionRequestHeaders["cookie"]//;} )
    for entry in ${cookie[@]}; do
      IFS='=' read -r key value <<<"$entry"
      [[ "$key" ]] && FictionRequestCookie["$key"]="${value}"
    done
  fi
  
  if [[ "${FictionRequest[method]}" == "POST" ]] && ((${FictionRequestHeaders['content-length']:=0} > 0)); then
    FictionRequest[data]="FictionRequestData"
    local entry
    if [[ "${FictionRequestHeaders["content-type"]}" == "application/x-www-form-urlencoded" ]]; then
      IFS='&' read -rN "${FictionRequestHeaders["content-length"]}" -a data
      for entry in "${data[@]}"; do
        entry="${entry%%$'\r'}"
        FictionRequestData["${entry%%=*}"]="${entry#*:}"
      done
    elif [[ "${FictionRequestHeaders["content-type"]}" == "application/json" ]]; then
      read -N "${FictionRequestHeaders["content-length"]}" post_data
      json_trim "${post_data%%$'\r'}" true true
      json_to_arr "$json_trim_output" FictionRequestData "" true
    else
      read -rN "${FictionRequestHeaders["content-length"]}" data
      FictionRequestData["raw"]="${data%%$'\r'}"
    fi
  fi
  filename="$serverTmpDir/output_$RANDOM"
  fiction.router >"$filename"
  [ -z "${FictionResponse["status"]}" ] && FictionResponse["status"]="200"
  printf '%s %s\n' "HTTP/1.1" "${FictionResponse["status"]}"
  local routetype="$type"

  if [[ -z "$filetype" || "$filetype" == "auto" ]]; then
    if which file 2>&1 >/dev/null; then
      local _ char type
      subshell type file --mime "$filename"
      IFS=' ' read _ type char <<<"$type"
      FictionResponseHeaders["content-type"]="${type//;/}"
      unset _ type char
    else
      FictionResponseHeaders["conten-type"]="application/octet-stream"
    fi
  else
    FictionResponseHeaders["content-type"]="${filetype}"
  fi

  if [[ "${FictionResponseHeaders["content-type"]}" == text/html && "$routetype" != cgi ]]; then
    local output
    _read_file output "$filename"
    if [[ "${output::6}" != '<html>' && "${output::15}" != '<!DOCTYPE html>' ]]; then
      {
        cat <<- EOF 
          <!DOCTYPE html>
          <html>
            <head>
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
                ${FictionResponse[head]}$FICTION_META
            </head>
EOF
        [[ "${output::5}" == "<body" ]] && echo "$output" || echo "<body>$output</body>";
        [[ "${Fiction[plugins@v]}" =~ "lucide-icons" ]] && echo '<script>lucide.createIcons();</script>'
        echo "</html>";
      } > "$filename";
    fi
  fi
  subshell filesize wc -c "$filename"
  read size filename <<<"$filesize"
  FictionResponseHeaders["content-length"]="${size:=0}"
  if [[ "$routetype" != "cgi" ]]; then
    for key in "${!FictionResponseHeaders[@]}"; do
      printf '%s: %s\n' "${key,,}" "${FictionResponseHeaders[$key]}"
    done
    for value in "${FictionResponseCookie[@]}"; do
      printf 'Set-Cookie: %s\n' "$value"
    done
    printf "\n"
  fi
  cat "$filename"
  printf "\n"
  rm "$filename"
  local time2
  subshell time2 date +%s%3N
  local time=$((time2-time1))
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
  case "${FictionResponse[status]}" in
    2[0-9][0-9]) local status="${_green}${FictionResponse[status]}${_nc}" ;;
    3[0-9][0-9]) local status="${_yellow}${FictionResponse[status]}${_nc}" ;;
    4[0-9][0-9]|5[0-9][0-9]) local status="${_red}${FictionResponse[status]}${_nc}" ;;
    *) status="${FictionResponse[status]}"
  esac
  builtin printf -v timestamp "%(%d/%m/%y %H:%M:%S)T"
  if [[ ${Fiction[mode]} == development ]]; then
    cat << EOF >&2
${_gray}${timestamp}${_nc} ${FictionRequest[version]} ${FictionRequest[method]} ${FictionRequest[path]} $status in $time ($size)
Handled by: $handled_by
EOF
    [[ "${Fiction[logs.show_addr]}" = true ]] && printf "%s\n" "Address: ${FictionRequestHeaders[x-forwarded-for]:=${FictionRequest[addr]}}" >&2

    if "${Fiction[logs.show_headers]:=false}"; then
      printf "%s\n" "Headers: " >&2
      for key in ${!FictionRequestHeaders[@]}; do 
        printf "%s\n" "${_bold}$key:${_nc} ${FictionRequestHeaders[$key]}" >&2;
      done
    elif "${Fiction[logs.show_ua]:=false}"; then
        printf "%s\n" "Headers: " >&2
    fi
  else
    { 
      printf "%s" "${_gray}${timestamp}${_nc} "
      "${Fiction[logs.show_addr]:=false}" && printf "%s" "$REMOTE_ADDR"
      printf "%s\n" " ${FictionRequest[method]} ${FictionRequest[path]} $status $time"
    }  >&2
  fi
  unset status handled_by routetype size time
  exit
}

# HelperFns

function fiction.addServerAction() {
  [ -z "$1" ] && return
  subshell hash _hash "$1"
  local json path="/__server-action_$hash" routes=""
  subshell path2 _hash "${path::-3}"
  subshell routes __d "$serverTmpDir/.routes"
  [[ ! "$routes" =~ ${path2::-3} ]] && fiction.serve "${path::-3}" "$1" "" api >&2
  [[ $? == 0 ]] && printf "%s" "serverAction('${path::-3}')" || return
}


function fiction.addMeta() {
  FictionResponse[head]+="$@"$'\n'
}

function fiction.header.set() {
  [[ -z "$1" || -z "$2" ]] && return
  FictionResponseHeaders["$1"]="$2"
}

function fiction.session() {
  [ ! -f "$serverTmpDir/.sessions" ] && return 1
  local session csrf hash csrf m=false ou
  subshell hash _hash "$1"
  subshell ou __d "$serverTmpDir/.sessions"
  subshell ou _regex "${hash::-3}" "$ou"
  [ -n "$ou" ] && IFS=' ' read session csrf <<< "$ou" || return 1
  [[ "${hash::-3}" == "$session" ]] || return 1
  return 0
}

function fiction.response.cookie.set() {
  FictionResponseCookie+=("$1")
}

function fiction.session.set() {
  if [ ! -f "$serverTmpDir/.sessions" ]; then
    : >"$serverTmpDir/.sessions"
    local session session_hash token out
    subshell session generate_session_id
    subshell session_hash _hash "$session"
    subshell token generate_csrf_token
    subshell token _encode "$token"
    __e "${ssession::-3} $token" "$serverTmpDir/.sessions"
    fiction.cookie.set "session_id=${session}; HttpOnly; max-age=${1:-10000}"
    SESSION_ID="${session}"
  else
    local session session_hash token out
    subshell session generate_session_id
    subshell session_hash _hash "$session"
    subshell token generate_csrf_token
    subshell token _encode "$token"
    out+=$'\n'"${session_hash::-3} $token"
    __e "$out" "$serverTmpDir/.sessions"
    fiction.cookie.set "session_id=${session}; HttpOnly; max-age=${1:-10000}"
    SESSION_ID="${session}"
  fi
}

fiction.respond() {
  local output;
  [[ -z "$1" ]] && _error "At least one argument expected" >&2 && return 1
  FictionResponse["status"]="$1"
  [[ -z "$2" ]] && while read chunk; do output+="$chunk"$'\n'; done || local output="$2"
  echo "$output"
}



fiction.404() {
#  INCLUDE_DOM=false
#  Fiction[include_lucide]=false
  handled_by="fiction.404"
  fiction.header.set "server" "Fiction/${Fiction[version]//v}"
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

fiction.500() {
  handled_by="fiction.500"
  fiction.header.set "server" "Fiction/${Fiction[version]//v}"
  fiction.respond 500 <<- EOF
  <!DOCTYPE html>
	<html style="font-family: ui-sans-serif, system-ui, sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Noto Color Emoji';background-color:black;color:white;">
    <meta>
      <title>Server _error - Fiction</title>
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
  echo "Fiction ${Fiction[version]}"
  echo "Configuration:"
  for key in ${!Fiction[@]}; do
  echo "  $key: ${Fiction[$key]}"
  done
  echo "Defined routes:"
  for key in ${!FictionRoute[@]}; do
    echo "  $key -> ${FictionRoute[$key]}"
  done
  echo "Loaded modules:" 
  for key in ${!FictionModule[@]}; do
  echo "  $key: ${FictionModule[$key]}"
  done
  echo "Available functions:"
  local var=$(declare -F | sed -n -e '/fiction/ { /\./ p; }')
  echo "${var//declare -f/ }"

}


function fiction.serve() {
  # fiction.serve <from> <to:fn> <as> <type?> <headers?>
  local funcname route
  [[ "$FICTION_HOTRELOAD" ]] && return
  [[ -z "$1" || -z "$2" ]] && return 1
  mktmpDir
  local type="${4:-static}"
  [[ "${FictionRoute["$1"]}" ]] && _error "Dublicate of existing route $1" && return 1 || FictionRoute["$1"]="$3"
  [[ $type == cgi ]] && [ ! -x "$2" ] && _error "$2 is not an executable. Check if the file exists and has executable permission" && return 1
  funcname="$2";
  route="$1"
  if [ ! -f "$serverTmpDir/.routes" ]; then
    : >"$serverTmpDir/.routes"
    __e "$type ${3:-auto} $route $funcname" "$serverTmpDir/.routes"
  else
    local ou 
    subshell ou __d "$serverTmpDir/.routes"
    ou+=$'\n'"$type ${3:-auto} $route $funcname"
    __e "$ou" "$serverTmpDir/.routes"
  fi
  "${FICTION_BUILD:-false}" || echo "[${_white}+${_nc}] Added ${type} route: from ${_bold}'$1'${_nc} to ${_bold}'$2'${_nc} ${3:+as '$3'}"
}

function fiction.serveDynamic() {
  # FictionServeDynamicPath <from> <to:fn> <as>
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
	[[ "$FICTION_SERVER" ]] && { _error "another instance of fiction.server is already running"; return 1; }
	FICTION_SERVER=true
  [[ -v Fiction[mode] ]] || Fiction[mode]="production"
  if [[ -z "${FictionRoute['/favicon.ico']}" ]]; then 
    declare -A _hh=([cache-control]="public,max-age=86400" [age]=0)
    fiction.serveFile "${FICTION_PATH}favicon.ico" "/favicon.ico" "" "_hh" >/dev/null

  fi
  [[ "$FICTION_BUILD" || "$FICTION_HOTRELOAD" ]] && return
  printf "\n%s\n" "Fiction (${_green}${Fiction[version]}${_nc})"
  i=1
  for route in ${!FictionModule[@]}; do
    if ((i < ${#FictionModule[@]})); then 
      echo "├─ $route"
    elif ((i = ${#FictionModule[@]})); then
      echo "└─ $route"
      break
    fi
    ((i++))
  done
  #[[ "${Fiction[include_wasm]}" == true && "${Fiction[ssl.enabled]:=false}" == false ]] && _error "Running the website with WASM included on HTTP. Modern browsers will not allow WASM initialization from HTTP origin. In case it's a development server, consider using ncat for running a temporary HTTPS server." && return 1
  mktmpDir
  trap clean EXIT;
  unset origaddress address port arg attr
  case "${Fiction[core]}" in
    bash)
      if "${Fiction[ssl.enabled]:=false}"; then
        _error "HTTPS isn't available in development core. Use ncat or socat for HTTPS server"
        exit 1
      else
        [ ! -f "${FictionModule[accept]}" ] && _error "\`accept\` is not found in ${Fiction[path]}" && return 1;
        enable -f "${FictionModule[accept]}" accept;
        [[ "${Fiction[port]}" = 80 ]] && \
        echo -e "\nServer address: http://${Fiction[address]} (${FICTION_MODE:-${Fiction[mode]}} mode)" || \
        echo -e "\nServer address: http://${Fiction[address]}:${Fiction[port]} (${FICTION_MODE:-${Fiction[mode]}} mode)";
        {
          while true; do
            accept -b "${Fiction[address]}" -r REMOTE_ADDR "${Fiction[port]}";
            if [[ -n "$ACCEPT_FD" ]]; then
              fiction.processHTTP <&${ACCEPT_FD} >&${ACCEPT_FD};
              exec {ACCEPT_FD}>&-;
            fi
          done
        } &
        SERVER_PID=$!
        [[ ${Fiction[mode]} =~ dev || ${Fiction[hot_reload]} = true ]] && _hotreload &
        HOTRELOAD_PID=$!
        while read line; do
          case "$line" in
            exit|quit|q|stop) exit ;; 
          esac
        done
      fi
    ;;
    nc | netcat | ncat | socat)
      _buildWorker
      echo -n "Server address: ";
      if "${Fiction[ssl.enabled]:=false}"; then
        [[ "${Fiction[port]}" = 443 ]] && \
          echo -n "https://${Fiction[address]}" || \
          echo -n "https://${Fiction[address]}:${Fiction[port]}";
      else
        [[ "${Fiction[port]}" = 80 ]] && \
          echo -n "http://${Fiction[address]}" || \
          echo -n "http://${Fiction[address]}:${Fiction[port]}";
      fi
      echo " (${FICTION_MODE:-${Fiction[mode]}} mode)";
      case "${Fiction[core]:-socat}" in
      socat)
        which socat >/dev/null || { _error "cannot find socat binary" && return 1; }
        if "${Fiction[ssl.enabled]:=false}"; then
          ( 
            exec -a "fiction" socat openssl-listen:"${Fiction[port]}",bind="${Fiction[address]}",verify=0,${Fiction[ssl.cert]:+cert="${Fiction[ssl.cert]}",}${Fiction[ssl.key]:+key="${Fiction[ssl.key]}",}reuseaddr,fork SYSTEM:"$serverTmpDir/job.sh";
          ) &
        else
          ( exec -a "fiction" socat TCP-LISTEN:${Fiction[port]},bind="${Fiction[address]}",reuseaddr,fork EXEC:"$serverTmpDir/worker.sh"; ) &
        fi
      ;;
      ncat)
        which ncat >/dev/null || { _error "cannot find ncat binary" && return 1; }
        if "${Fiction[ssl.enabled]:=false}"; then
          ( 
            exec -a "fiction" ncat -klp "${Fiction[port]}" -c "$serverTmpDir/worker.sh" --ssl ${Fiction[ssl.cert]:+--ssl-cert "${Fiction[ssl.cert]}"} ${Fiction[ssl.key]:+--ssl-key "${Fiction[ssl.key]}"}; 
          ) &
        else
          ( exec -a "fiction" ncat -klp "${Fiction[port]}" -c "$serverTmpDir/worker.sh"; ) &
        fi
      ;;
      nc | netcat)
        nc --version 2> 1 > /dev/null && nc_path="nc.traditional" || nc_path="nc";
        which "$nc_path" >/dev/null || { _error "cannot find netcat binary" && return 1; }
        if "${Fiction[ssl.enabled]:=false}"; then
          _error "HTTPS is not supported in legacy netcat mode" 1>&2
        else
          (
            while true; do
              exec -a "fiction" $nc_path -vklp "${Fiction[port]}" -e "$serverTmpDir/worker.sh";
              (($? != 0)) && break
            done
          ) &

        fi
      ;;
      esac
      SERVER_PID=$!
      [[ ${Fiction[mode]} == development || ${Fiction[hot_reload.enabled]} = true ]] && _hotreload >&2 &
      HOTRELOAD_PID=$!
      while read line; do
        case "$line" in
          exit|quit|q|stop) exit ;;
        esac
      done
    ;;
  esac
}



_hotreload() {
  FICTION_HOTRELOAD=true
  FICTION_NESTED=true
  local __files=()
  local file
  for file in ${Fiction[hot_reload.files]//@a }; do
    local _value="${Fiction[hot_reload.files.$file]}"
    [[ "${value::1}" != '/' ]] && _value="${FICTION_PATH}${_value}"
    [[ "$_value" == *' '* ]] && __files+=("'$_value'") || __files+=("$_value")
  done

  _warn "Hot-Reload enabled. This is an experimental feature, use it with caution."

  if which inotifywait >/dev/null 2>&1; then
    i=0
    inotifywait -qm --event modify --format '%w' ${__files[@]} | while read -r file; do
      ((i == 1)) && i=0 && continue  
      [[ ! "$file" =~ \.shx|\.bashx ]] && { source "$file" && printf "%s\n" "[$_green✓$_nc] Reloaded $file" || printf "%s\n" "[${_red}x${_nc}] Failed to reload $file"; } || BASHX_VERBOSE=true @import "$file"; 
      if [[ ${Fiction[core]} != bash ]]; then
        _buildWorker
      else
        _buildWorker true
        i=1
      fi
    done
  else
    _warn "inotify-tools package is not installed, Hot-Reload will use md5sum to compare files every ${Fiction[hot_reload_interval]:=2}s"
    local -A _files=()
    for file in "${__files[@]}"; do
      subshell _var md5sum "$file"
      _files["$file"]="$_var";
      unset _var
    done

    while sleep ${Fiction[hot_reload.interval]}; do
      for file in "${__files[@]}"; do
        subshell file2 md5sum "$file"
        [[ "$file2" == "${_files["$file"]}" ]] && continue
        printf "%s\n" "(hot-reload) Reloading $file..."
        [[ ! "$file" =~ \.shx|\.bashx ]] && { source "$file" && printf "%s\n" "[$_green✓$_nc] Reloaded $file" || printf "%s\n" "[${_red}x${_nc}] Failed to reload $file"; } || BASHX_VERBOSE=true @import "$file"; 
        [[ ${Fiction[core]} != bash ]] && _buildWorker
        _files["$file"]="$file2";
      done
    done
  fi
}


_build() {
  echo "Initializing build..."
  subshell time date +%s%3N
  Fiction[mode]=build
  [[ "$2" ]] && Fiction[default_index]="$2"
  [[ "$3" ]] && target_dir="$3"
  BASHX_VERBOSE=true
  FICTION_NESTED=true
  FICTION_BUILD=true
  for plugin in ${Fiction[plugins@v]//\'}; do
      case "$plugin" in
        "tailwindcss") FictionResponse[head]+='<script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>' ;;
        "lucide-icons") FictionResponse[head]+='<script src="https://unpkg.com/lucide@latest"></script>' ;;
        "dom") subshell _dom_contents cat "$dom_path"; FictionResponse[head]+="<script>${_dom_contents}</script>" ;;
      esac
    done
    for file in "${FICTION_PATH}"pages/*; do
      if [[ "$file" == *.shx ]]; then 
        [[ -v FictionModule[bashx] ]] && bashx "$file" || { _error "cannot load bashx file without bashx module"; exit 1; }
      else
        source "$file"
      fi
  done
  [[ $? > 0 ]] && exit
  while read route; do
    read type filetype route func <<< "$route";
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
    ${func} ${funcargs//\"/\\\"} >"$path/$type.html" & 
    pid=$!
    s='-\|/'; i=0; while kill -0 $pid 2>/dev/null; do i=$(((i+1)%4)); printf "\r[${s:$i:1}] $route\r"; sleep .1; done
    wait $pid
    if [[ "$filetype" == text/html && "$type" != cgi ]]; then
        local output
        _read_file output "$path/$type.html"
        if [[ "${output::6}" != '<html>' && "${output::15}" != '<!DOCTYPE html>' ]]; then
          {
            cat <<- EOF 
          <!DOCTYPE html>
          <html>
            <head>
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
                ${FictionResponse[head]}$FICTION_META
            </head>
EOF
            [[ "${output::5}" == "<body" ]] && echo "$output" || echo "<body>$output</body>";
            [[ "${Fiction[plugins@v]}" =~ "lucide-icons" ]] && echo '<script>lucide.createIcons();</script>'
            echo "</html>";
          } > "$path/$type.html";
        fi
    fi
    exit=$?
    [[ $exit == 0 ]] && [ -f "$path/$type.html" ] && echo "[$_green✓$_nc] $route (${path%%\/}/${type}.html)" ||  echo "[${_red}x${_nc}] $route ($exit)"
  done < <(__d "$serverTmpDir/.routes")
  rm -rf "$serverTmpDir"
  echo "Build completed. ($(($(date +%s%3N)-time))ms)"
}

_buildWorker() {
  (
    echo "#!/bin/bash"
    echo "FICTION_PATH='$FICTION_PATH'"
    declare -A
    unset -f fiction.server @cache @prerender
    [[ "${FictionModule[bashx]}" ]] && unset -f @import bashx mktmpDir @render_type @wrapper _render _conditionalRender
    declare | \
      grep -vE '(^DBUS_SESSION_BUS_ADDRESS|^WAYLAND_|^FUNCNAME|^LANG|^ICEAUTHORITY*|^MEMORY_PRESSURE*|^LS_COLORS*|^HOST*|^WASMER*|^Fiction.*=|^chunk=|^newblock=|^out1=|^GPG|^SHELL|^SESSION_|^OS|^KDE_*|^GTK*|^XDG*|^XKB*|^PAM*|^KONSOLE*|^SSH_*|^QT_*|^PWD|^OLDPWD|^TERM|^HOME|^USER|^PATH|^BASH_*|^BASHOPTS|^EUID|^PPID|^SHELLOPTS|^UID)'
      [[ -z "$1" ]] && cat <<EOF
HEADERS=""
while read -r val; do
  val="\${val//$'\r'/}"
  HEADERS+="\$val"$'\n'
  [[ "\${val,,}" =~ 'content-length' ]] && IFS=':' read key value <<< "\${val,,}"
  [[ "\${#val}" < 1 ]] && break
done
[[ "\${value// }" -gt 1 ]] && { read -rn \${value// } -t1 data; [[ \${#data} > 1 ]] && HEADERS+="\${data//$'\r'/}"$'\n'; unset key value data; }
[[ "\$NCAT_REMOTE_ADDR" ]] && REMOTE_ADDR="\$NCAT_REMOTE_ADDR" || REMOTE_ADDR="\$FICTION_PEERADDR"
$([[ "$workerargs" ]] && echo 'set $workerargs')
fiction.processHTTP <<<"\$HEADERS"
EOF
  ) >"$serverTmpDir/worker.sh";
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
          [[ "${Fiction[mode]}" == development ]] && BASHX_VERBOSE=true
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
  Fiction[default_index]="${FICTION_PATH}pages/${Fiction[default_index]:=index.shx}"
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

clean() {
  echo -e "\nStopping the server..."
  [[ -n "$serverTmpDir" && -d "$serverTmpDir" ]] && rm -rf "$serverTmpDir"
  [[ "$SERVER_PID" ]] && kill $SERVER_PID 2>/dev/null
  [[ "$HOTRELOAD_PID" ]] && kill $((HOTRELOAD_PID+2)) $((HOTRELOAD_PID+3)) 2>/dev/null
  exit
}

declare_objects() {
  [[ ${Fiction[routes]} != FictionRoute ]] && unset FictionRoute && declare -gn FictionRoute="${Fiction[routes]}"
  [[ ${Fiction[modules]} != FictionModule ]] && unset FictionModule && declare -gn FictionModule="${Fiction[modules]}"
  [[ ${Fiction[response]} != FictionResponse ]] && unset FictionResponse && declare -gn FictionResponse="${Fiction[responses]}"
  [[ ${Fiction[request]} != FictionRequest ]] && unset FictionRequest && declare -gn FictionRequest="${Fiction[requests]}"
}

#_modulesLoader /home/tirito/fiction/framework/modules/shelljq
#_configParser
#exit
if ! (return 0 2>/dev/null); then
  case "$1" in
  run|dev)
    _modulesLoader
    _configParser
    [[ "$2" ]] && Fiction[default_index]="$2"
    [[ "$1" == dev ]] && Fiction[mode]=development || Fiction[mode]=production
    BASHX_VERBOSE=true
    FICTION_NESTED=true
    for plugin in ${Fiction[plugins@v]//\'}; do
      case "$plugin" in
        "tailwindcss") FictionResponse[head]+='<script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>' ;;
        "lucide-icons") FictionResponse[head]+='<script src="https://unpkg.com/lucide@latest"></script>' ;;
        "dom") subshell _dom_contents cat "$dom_path"; FictionResponse[head]+="<script>${_dom_contents}</script>" ;;
      esac
    done
    for file in "${FICTION_PATH}"pages/*; do
      if [[ "$file" == *.shx ]]; then 
        [[ -v FictionModule[bashx] ]] && bashx "$file" || { _error "cannot load bashx file without bashx module"; exit 1; }
      else
        source "$file"
      fi
    done
    fiction.server
  ;;
  build) 
    _modulesLoader
    _configParser
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
  [[ "$FICTION_HOTRELOAD" ]] || _modulesLoader
  if [[ "$FICTION_NESTED" != true ]]; then
    declare_objects
    if [[ "${Fiction[mode]}" == build ]]; then 
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
