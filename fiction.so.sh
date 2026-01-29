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
  [mode]="${FICTION_MODE:-production}"
  [core]="socat"
  [expose_addr]=true
  [show_headers]=true
  [hot_reload]=false
  [hot_reload_files]="$FICTION_PATH/pages/* ${FICTION_PATH}fiction.so.sh"
  [encode_routes]=false # Whether encode routes storage file or not
  [default_index]="pages/index.shx" # Default index file to execute (bashx, fiction run/dev/build)
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
# - parseAndPrint
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

function error() {
  [[ ${#FUNCNAME[@]} > 1 ]] && echo -n "(${FUNCNAME[1]}) " >&2
  echo "${_red}Error:${_nc} ${1}" >&2
  #[[ "$2" ]] && FUNCTION_ERROR=
}

function warn() {
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

#declare -a FictionDynamicRoute
#declare -A FictionRouteContentType
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



parsePost() {
  if [[ "${FictionRequest[method]}" =~ "POST"|"PATCH"|"PUT" ]] && ((${FictionRequestHeaders['content-length']:=0} > 0)); then
  local entry
  if [[ "${FictionRequestHeaders["content-type"]}" == "application/x-www-form-urlencoded" ]]; then
    IFS='&' read -rN "${FictionRequestHeaders["content-length"]}" -a data
    for entry in "${data[@]}"; do
    entry="${entry%%$'\r'}"
    POST["${entry%%=*}"]="${entry#*:}"
    done
  elif [[ "${FictionRequestHeaders["content-type"]}" == "application/json" ]]; then
    read -N "${FictionRequestHeaders["content-length"]}" data
    json_to_arr "${data%%$'\r'}" POST "" true
    eval $json_to_arr_output
  else
    read -rN "${FictionRequestHeaders["content-length"]}" data
    POST["raw"]="${data%%$'\r'}"
  fi
  unset entry
  fi
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
        HTTPS="${Fiction[https]}" \
        SCRIPT_FILENAME="$func" \
        HTTP_USER_AGENT="${FictionRequestHeaders[user-agent]}" \
        HTTP_COOKIE="${FictionRequestHeaders[cookie]}" \
        $func;
        )
      else
        parsePost
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

function parseAndPrint() {
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
  for entry in "${data[@]}"; do
    FictionRequestQuery["${entry%%=*}"]="${entry#*=}"
  done
  IFS=';' read -ra cookie <<<"${FictionRequestHeaders["cookie"]}"
  [ -n "${FictionRequestHeaders["Cookie"]}" ] && ((${#cookie[@]} < 1 )) && cookie+=( ${FictionRequestHeaders["cookie"]//;} )
  for entry in ${cookie[@]}; do
    IFS='=' read -r key value <<<"$entry"
    [[ "$key" ]] && FictionRequestCookie["$key"]="${value}"
  done
  if [[ "${FictionRequest[method]}" == "POST" ]] && ((${FictionRequestHeaders['content-length']:=0} > 0)); then
    local entry
    if [[ "${FictionRequestHeaders["content-type"]}" == "application/x-www-form-urlencoded" ]]; then
      IFS='&' read -rN "${FictionRequestHeaders["content-length"]}" -a data
      for entry in "${data[@]}"; do
        entry="${entry%%$'\r'}"
        FictionRequestData["${entry%%=*}"]="${entry#*:}"
      done
    elif [[ "${FictionRequestHeaders["content-type"]}" == "application/json" ]]; then
      read -N "${FictionRequestHeaders["content-length"]}" data
      json_to_arr "${data%%$'\r'}" FictionRequestData "" true
      eval "$json_to_arr_output"
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
    local _ char type
    subshell type file --mime "$filename"
    IFS=' ' read _ type char <<<"$type"
    which file 2>&1 >/dev/null && FictionResponseHeaders["content-type"]="${type//;/}"
    unset _ type char
  else
    FictionResponseHeaders["content-type"]="${filetype}"
  fi

  if [[ "${FictionResponseHeaders["content-type"]}" =~ html && "$routetype" != cgi ]]; then
    local isdoctype=false ishtml=false isbody=false iscbody=false ishead=false ischtml=false ischead=false
    local output
    subshell output cat "$filename"
    if [[ "${output::6}" != '<html>' && "${output::15}" != '<!DOCTYPE html>' ]]; then
    {
      cat << EOF 
<!DOCTYPE html>
<html>
  <head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  ${FictionResponse[head]}$FICTION_META
EOF
    "${Fiction[include_dom]:-false}" && echo "<script>" && cat "$dom_path" && echo "</script>";
    if "${Fiction[include_wasm]:-false}"; then
      cat << EOF
        <script>
    let queue = [];
    let stdoutBuffer = "";
    let stderrBuffer = "";
    window.execute = async function execute(command,id) {
    if (id == undefined) id = null;
    return new Promise(() => queue.push([command,id]));
    }
  </script>
EOF
      if declare -F wasmBundle >/dev/null; then
        fiction.header.set "Cross-Origin-Opener-Policy" "same-origin"
        fiction.header.set "Cross-Origin-Embedder-Policy" "require-corp"
        [[ -v FICTION_ROUTE ]] || FICTION_ROUTE="${FictionRequest[path]}"
        [[ -v FICTION_VERSION ]] || FICTION_VERSION="${Fiction[version]}"
        exportVariable FICTION_VERSION FICTION_ROUTE
        wasmBundle
      else
        error "Cannot load WASM module, file isn't loaded or not found"
      fi
    fi;
    "${Fiction[include_tailwind]:-true}" && echo '<script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>';
    "${Fiction[include_lucide]:=true}" && echo '<script src="https://unpkg.com/lucide@latest"></script>';
    echo '</head>';
    [[ "${output::5}" == "<body" ]] && echo "$output" || echo "<body>$output</body>";
    "${Fiction[include_lucide]}" && echo '<script>lucide.createIcons();</script>'
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
  if [[ ${Fiction[mode]} =~ dev ]]; then
    cat << EOF >&2
${_gray}${timestamp}${_nc} ${FictionRequest[version]} ${FictionRequest[method]} ${FictionRequest[path]} $status in $time ($size)
Handled by: $handled_by
EOF
[[ "${Fiction[expose_addr]}" = true ]] && echo "Address: ${FictionRequestHeaders[x-forwarded-for]:=${FictionRequest[addr]}}" >&2

    if [[ "${Fiction[show_headers]}" = true ]]; then
      echo "Headers: " >&2
      for key in ${!FictionRequestHeaders[@]}; do 
        echo "${_bold}$key:${_nc} ${FictionRequestHeaders[$key]}" >&2;
      done
    fi
  else
    echo "${_gray}${timestamp}${_nc} ${Fiction[expose_addr]:+$REMOTE_ADDR} ${FictionRequest[method]} ${FictionRequest[path]} $status $time" >&2
  fi
  unset status handled_by routetype size time
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
  FICTION_META+="$@"$'\n'
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
  [[ -z "$1" ]] && error "At least one argument expected" >&2 && return 1
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
      <title>Server Error - Fiction</title>
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
  if [[ "${Fiction[mode]}" == build ]]; then
    [[ "$3" == text/html ]] || return
  fi
  [[ "${FictionRoute["$1"]}" ]] && error "Dublicate of existing route $1" && return 1 || FictionRoute["$1"]="$3"
  [[ $type == cgi ]] && [ ! -x "$2" ] && error "$2 is not an executable. Check if the file exists and has executable permission" && return 1
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
  echo "[${_white}+${_nc}] Added ${type} route: from ${_bold}'$1'${_nc} to ${_bold}'$2'${_nc} ${3:+as '$3'}"
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
  [[ -z "$1" ]] && error "Expected \$1, but got null" && fiction.500 && return
  fiction.header.set "server" "Fiction/${Fiction[version]}"
  fiction.header.set "location" "$1"
  fiction.respond 301
}

function fiction.serveFile() {
  [ ! -f "$1" ] && error "$1 is not a file" && return 1
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
    error "$1 is not a directory"
    return 1;
  fi
}


function fiction.server() {
  [[ -v Fiction[mode] ]] || Fiction[mode]="production"
  if [[ -z "${FictionRoute['/favicon.ico']}" ]]; then 
    declare -A _hh=([cache-control]="public,max-age=86400" [age]=0)
    fiction.serveFile "${FICTION_PATH}favicon.ico" "/favicon.ico" "" "_hh" >/dev/null

  fi
  [[ "$FICTION_BUILD" || "$FICTION_HOTRELOAD" ]] && return
  local address port origaddress="$1";
  [[ $origaddress ]] || error "Bind address required"
  if [[ "$origaddress" =~ "https://" ]]; then
    Fiction[https]=true;
    origaddress="${origaddress//https:\/\//}";
  else
    [[ "$origaddress" =~ "http://" ]] && origaddress="${origaddress//http:\/\//}";
  fi
  IFS=':' read -r address port <<< "$origaddress";
  [[ -z "$port" ]] && { "${Fiction[https]:=false}" && port=443 || port=80; }
  Fiction[bind_address]="$address"
  Fiction[bind_port]="$port"
  shift;
  if [[ "$#" > 0 ]]; then
    for arg in "${@}"; do
      IFS='=' read key value <<< "$arg";
      [[ -z "$value" ]] && continue;
      case "$key" in
        ssl)  Fiction[https]=true ;;
        ssl_cert) 
          [ -f "$value" ] && Fiction[ssl_cert]="$value" || {
            error "ssl_cert: $value: no such file" && return 1
          }
        ;;
        ssl_key)
          [ -f "$value" ] && Fiction[ssl_key]="$value" || {
            error "ssl_key: $value: no such file" && return 1
          }
        ;;
        include_lucide) Fiction[include_lucide]="$value" ;;
        include_tailwind) Fiction[include_tailwind]="$value" ;;
        include_wasm) Fiction[include_wasm]="$value" ;;
        expose_addr) Fiction[expose_addr]="$value" ;;
        core) Fiction[core]="$value" ;;
        *)
          error "Illegal option: $key" 1>&2;
          return 1
        ;;
      esac
    done
    unset key value
  fi
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
  [[ "${Fiction[include_wasm]}" == true && "${Fiction[https]:=false}" == false ]] && error "Running the website with WASM included on HTTP. Modern browsers will not allow WASM initialization from HTTP origin. In case it's a development server, consider using ncat for running a temporary HTTPS server." && return 1
  mktmpDir
  trap clean EXIT;
  unset origaddress address port arg attr
  case "${Fiction[core]}" in
    bash)
      if "${Fiction[https]:=false}"; then
        error "HTTPS isn't available in development core. Use ncat or socat for HTTPS server"
        exit 1
      else
        [ ! -f "${FictionModule[accept]}" ] && error "\`accept\` is not found in ${Fiction[path]}" && return 1;
        enable -f "${FictionModule[accept]}" accept;
        [[ "${Fiction[bind_port]}" = 80 ]] && \
        echo -e "\nServer address: http://${Fiction[bind_address]} (${FICTION_MODE:-${Fiction[mode]}} mode)" || \
        echo -e "\nServer address: http://${Fiction[bind_address]}:${Fiction[bind_port]} (${FICTION_MODE:-${Fiction[mode]}} mode)";
        (
          while true; do
            accept -b "${Fiction[bind_address]}" -r REMOTE_ADDR "${Fiction[bind_port]}";
            if [[ -n "$ACCEPT_FD" ]]; then
              parseAndPrint <&${ACCEPT_FD} >&${ACCEPT_FD};
              exec {ACCEPT_FD}>&-;
            fi
          done
        ) &
        SERVER_PID=$!
        [[ ${Fiction[mode]} =~ dev || ${Fiction[hot_reload]} = true ]] && _hotreload &
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
      if "${Fiction[https]:=false}"; then
        [[ "${Fiction[bind_port]}" = 443 ]] && \
          echo -n "https://${Fiction[bind_address]}" || \
          echo -n "https://${Fiction[bind_address]}:${Fiction[bind_port]}";
      else
        [[ "${Fiction[bind_port]}" = 80 ]] && \
          echo -n "http://${Fiction[bind_address]}" || \
          echo -n "http://${Fiction[bind_address]}:${Fiction[bind_port]}";
      fi
      echo " (${FICTION_MODE:-${Fiction[mode]}} mode)";
      case "${Fiction[core]:-socat}" in
      socat)
        which socat >/dev/null || { error "cannot find socat binary" && return 1; }
        if "${Fiction[https]:=false}"; then
          ( 
            exec -a "fiction" socat openssl-listen:"${Fiction[bind_port]}",bind="${Fiction[bind_address]}",verify=0,${Fiction[ssl_cert]:+cert="${Fiction[ssl_cert]}",}${Fiction[ssl_key]:+key="${Fiction[ssl_key]}",}reuseaddr,fork SYSTEM:"$serverTmpDir/job.sh";
          ) &
        else
          echo " (${FICTION_MODE:-${Fiction[mode]}} mode)";
          ( exec -a "fiction" socat TCP-LISTEN:${Fiction[bind_port]},bind="${Fiction[bind_address]}",reuseaddr,fork EXEC:''"$serverTmpDir"'/worker.sh'; ) &
        fi
      ;;
      ncat)
        which ncat >/dev/null || { error "cannot find ncat binary" && return 1; }
        if "${Fiction[https]:=false}"; then
          ( 
            exec -a "fiction" ncat -klp "${Fiction[bind_port]}" -c "$serverTmpDir/worker.sh" --ssl ${Fiction[ssl_cert]:+--ssl-cert "${Fiction[ssl_cert]}"} ${Fiction[ssl_key]:+--ssl-key "${Fiction[ssl_key]}"}; 
          ) &
        else
          ( exec -a "fiction" ncat -klp "${Fiction[bind_port]}" -c "$serverTmpDir/worker.sh"; ) &
        fi
      ;;
      nc | netcat)
        nc --version 2> 1 > /dev/null && nc_path="nc.traditional" || nc_path="nc";
        which "$nc_path" >/dev/null || { error "cannot find netcat binary" && return 1; }
        if "${Fiction[https]:=false}"; then
          error "HTTPS is not supported in legacy netcat mode" 1>&2
        else
          (
            while true; do
              exec -a "fiction" $nc_path -vklp "${Fiction[bind_port]}" -e "$serverTmpDir/worker.sh";
              (($? != 0)) && break
            done
          ) &
        fi
      ;;
      esac
      SERVER_PID=$!
      [[ ${Fiction[mode]} =~ dev || ${Fiction[hot_reload]} = true ]] && _hotreload >&2 &
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
  warn "Hot-Reload enabled. This is an experimental feature, use it with caution."
  local file
  if which inotifywait >/dev/null 2>&1; then
    i=0
    inotifywait -qm --event modify --format '%w' ${Fiction[hot_reload_files]} | while read -r file; do
      ((i == 1)) && i=0 && continue  
      [[ ! "$file" =~ \.shx|\.bashx ]] && { source "$file" && printf "%s\n" "[$_green✓$_nc] Reloaded $file" || printf "%s\n" "[${_red}x${_nc}] Failed to reload $file"; } || BASHX_VERBOSE=true @import "$file"; 
      [[ ${Fiction[core]} != bash ]] && _buildWorker
      i=1
    done
  else
    warn "inotify-tools package is not installed, Hot-Reload will use md5sum to compare files every 2s"
    declare -A _files=()
    for file in ${Fiction[hot_reload_files]}; do
      subshell _var md5sum "$file"
      _files["$file"]="$_var";
      unset _var
    done
    while sleep 2; do
      for file in ${Fiction[hot_reload_files]}; do
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
  bashx "${Fiction[default_index]}"
  [[ $? > 0 ]] && exit
  while read route; do
    read type filetype route func <<< "$route";
    [[ "$type" == "file" ]] && continue
    echo -ne "(-) $route...\r"
    path="${default_dir:=fiction_compiled}$route"
    [[ "$route" ]] && mkdir -p "$path"
    read func funcargs <<< "$func";
    ${func} ${funcargs//\"/\\\"} >"$path/$type.html" & 
    pid=$!
    s='-\|/'; i=0; while kill -0 $pid 2>/dev/null; do i=$(((i+1)%4)); printf "\r[${s:$i:1}] $route\r"; sleep .1; done
    wait $pid
    exit=$?
    [[ $exit == 0 ]] && [ -f "$path/$type.html" ] && echo "[$_green✓$_nc] $route (${path%%\/}/${type}.html)" ||  echo "[${_red}x${_nc}] $route ($exit)"
  done < <(__d "$serverTmpDir/.routes")
  rm -rf "$serverTmpDir"
  echo "Build completed. ($(($(date +%s%3N)-time))ms)"
}

_buildWorker() {
  { 
    echo "#!/bin/bash"
    echo "FICTION_PATH='$FICTION_PATH'"
    declare -A
    unset -f fiction.server @cache @prerender
    [[ "${FictionModule[bashx]}" ]] && unset -f @import bashx mktmpDir @render_type @wrapper _render _conditionalRender
    declare | \
      grep -vE '(^DBUS_SESSION_BUS_ADDRESS|^WAYLAND_|^FUNCNAME|^LANG|^ICEAUTHORITY*|^MEMORY_PRESSURE*|^LS_COLORS*|^HOST*|^WASMER*|^Fiction.*=|^chunk=|^newblock=|^out1=|^GPG|^SHELL|^SESSION_|^OS|^KDE_*|^GTK*|^XDG*|^XKB*|^PAM*|^KONSOLE*|^SSH_*|^QT_*|^PWD|^OLDPWD|^TERM|^HOME|^USER|^PATH|^BASH_*|^BASHOPTS|^EUID|^PPID|^SHELLOPTS|^UID)'
      cat <<EOF
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
parseAndPrint <<<"\$HEADERS"
EOF
  } >"$serverTmpDir/worker.sh";
  chmod +x "$serverTmpDir/worker.sh";
}

_modulesLoader() {
  for file in $FICTION_PATH/modules/*; do
    case "${file##*/}" in
      accept)
        [[ -v __modules[accept] ]] && continue
        FictionModule[accept]="$file"
      ;;
      ui)
        [[ -v __modules[ui] ]] && continue
        if [[ -f "$file/index.sh" ]]; then
          FictionModule[ui]="$file"
          source "$file/index.sh"
        else 
          error "cannot find UI module ($file/index.sh)"
        fi
      ;;
      bashx)
        [[ -v FictionModule[bashx] ]] && continue
        if [[ -f "$file/bashx" ]]; then
          FictionModule[bashx]="$file/bashx"
          [[ "${Fiction[mode]}" =~ dev ]] && BASHX_VERBOSE=true
          BASHX_NESTED=true 
          source "$file/bashx"
        else
          error "cannot find bashx ($file/bashx)"
        fi
      ;;
      bash-wasm)
        [[ -v FictionModule[wasm] ]] && continue
        if [[ -f "$file/index.sh" ]]; then
          FictionModule[wasm]="$file"
          source "$file/index.sh"
        else
          error "cannot find WASM module ($file/index.sh)"
        fi
      ;;
    esac
  done
}

_helpmsg() {
  cat << EOF
Usage: $0 [action] [arguments]

Available actions:
  run   [file?]           Start the production server using <file> (src/index.shx default)
  dev   [file?]           Start the development server using <file> (src/index.shx default)
  build [file?] [target?] Build the routes defined in <file> into <target> directory (fiction_compiled default)
  version                 Return server version
  help                    Show this message
EOF
}

clean() {
  echo -e "\nStopping the server..."
  [[ -n "$serverTmpDir" && -d "$serverTmpDir" ]] && rm -rf "$serverTmpDir"
  [[ "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null
  #kill -$$
  exit
}

declare_objects() {
  [[ ${Fiction[routes]} != FictionRoute ]] && unset FictionRoute && declare -gn FictionRoute="${Fiction[routes]}"
  [[ ${Fiction[modules]} != FictionModule ]] && unset FictionModule && declare -gn FictionModule="${Fiction[modules]}"
  [[ ${Fiction[response]} != FictionResponse ]] && unset FictionResponse && declare -gn FictionResponse="${Fiction[responses]}"
  [[ ${Fiction[request]} != FictionRequest ]] && unset FictionRequest && declare -gn FictionRequest="${Fiction[requests]}"
}

if ! (return 0 2>/dev/null); then
  case "$1" in
  run|dev)
    _modulesLoader
    [[ "$2" ]] && Fiction[default_index]="$2"
    [[ "$1" == dev ]] && FICTION_MODE=development || FICTION_MODE=production
    BASHX_VERBOSE=true
    FICTION_NESTED=true
    bashx "${Fiction[default_index]}"
  ;;
  build) _modulesLoader; _build && exit ;;
  version)
    cat << EOF
Fiction ${Fiction[version]}
Copyright (C) Tirito6626, notnulldaemon 2025
EOF
  ;;
  help) _helpmsg ;;
  *)
    error "Invalid action: $1"
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
