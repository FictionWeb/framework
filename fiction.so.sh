#!/bin/bash
# The Fiction(R) Library, powered by insane people
FICTION_HTTP_ERROR_BEGIN="<html style='font-family:sans-serif;background-color:#212121;color:white;'><title>Error</title><center>"
FICTION_HTTP_ERROR_END="<hr><p>Fiction Web Server</h1></center></html>"
FICTION_PATH=$(readlink -f "${BASH_SOURCE[0]:-$0}")
FICTION_PATH="${FICTION_PATH//fiction.so.sh}"
FICTION_META=""
[[ ! -v _red ]] && { 
_green="$(tput setaf 2)"
_red="$(tput setaf 1)"
_yellow="$(tput setaf 3)"
_white="$(tput setaf 255)"
_bold="$(tput bold)"
_nc="$(tput sgr 0)"
}

# Main configuration object. It contains all options, paths, routes, arguments and modules
declare -gA Fiction=(
  [version]="v1.0.0-prerelease" # Server's version
  [path]="${FICTION_PATH}" # Fiction's absolute path
  # Pointers to child arrays. If pointers use custom value, Fiction* variables will reference custom values
  [routes]=FictionRoute 
  [modules]=FictionModule
  [response]=FictionResponse 
  [request]=FictionRequest 
  [core]="ncat"
  [expose_addr]=true
  [encode_routes]=false # Whether encode routes storage file or not
  [default_index]="index.shx" # Default index file to execute (bashx, fiction run/build)
)
#workerargs="-x"
declare -gA FictionRoute
declare -gA FictionResponse=(
  [status]=""
  [headers]=FictionResponseHeaders
  [cookie]=FictionResponseCookie
  [head]="" 
)
declare -gA FictionResponseHeaders FictionResponseCookie

declare -gA FictionRequest=(
  [headers]=FictionRequestHeaders
  [cookies]=FictionRequestCookie
  [query]=FictionRequestQuery
  [data]=FictionRequestData
)
declare -gA FictionRequestHeaders FictionRequestQuery FictionRequestData FictionRequestCookie
declare -gA FictionModule=( 
  # Example on adding module: 
  # FictionModule[bashx]="${Fiction[path]}/modules/bashx/bashx"
)
_green="$(tput setaf 2)"
_red="$(tput setaf 1)"
_white="$(tput setaf 255)"
_bold="$(tput bold)"
_nc="$(tput sgr 0)"
declare -a __funcs;

# Helper functions
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

  if [ -z "$DO_NOT_RERUN" ] && [ -n "$(declare -F "\\$1")" ]; then
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
  ! pidof fiction >/dev/null && [ -d "$FICTION_PATH/.fiction" ] && rm -rf $FICTION_PATH/.fiction/* 2>&1 >/dev/null
  serverTmpDir="$FICTION_PATH/.fiction/tmp_$(openssl rand -hex 16)"
  mkdir -p "$serverTmpDir"
  #echo $?
  if [[ $? > 0 ]]; then
    serverTmpDir="/tmp/.fiction/tmp_$(openssl rand -hex 16)"
    mkdir -p "$serverTmpDir"
  fi
  fi
}

function error() {
  [[ ${#FUNCNAME[@]} > 1 ]] && echo -n "(${FUNCNAME[1]}) " >&2
  echo "${_red}Error:${_nc} ${@}" >&2
}

function createState() {
  [[ -z "$1" || -z "$2" ]] && return
  local name="${1//\'}" value="${2//\'}"
  name="${name//\"}"
  value="${value//\"}"
  printf "const $name = useState('$value'); "
  printf -v "$name" "$value"
  if [[ $3 ]]; then
    el="${3//\'}"
    el="${el//\"}"
    printf "bindState(${1//\"}, '$el'); "
  fi
}

function setState() {
  [[ -z "$1" || -z "$2" ]] && return
  local name="${1//\'}" value="${2//\'}"
  name="${name//\"}"
  value="${value//\"}"
  printf "$name.set('$value'); "
  printf -v "$name" "%s" "$value"
}

function sendAction() {
  [[ "${2::2}" == '{"' ]] && local json="{\"type\":\"$1\",${3:+\"id\":\"$3\",}\"data\":$2 }" || local json="{\"type\":\"$1\",${3:+\"id\":\"$3\",}\"data\":\"$2\" }"
  echo "${json}"
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

__x4gT9q6=( "$(openssl rand -hex 32)" "$(openssl rand -hex 16)" );


__e() {
  "${Fiction[encode_routes]}" && openssl enc -aes-256-cbc -K "${__x4gT9q6[0]}" -iv "${__x4gT9q6[1]}" -out "$2" <<< "$1" || echo "$1" > "$2"
}

__d() {
  "${Fiction[encode_routes]}" && openssl enc -d -aes-256-cbc -K "${__x4gT9q6[0]}" -iv "${__x4gT9q6[1]}" -in "$1" || cat "$1"
}


sendError() {
  set -- $1
  printf '%s\n' "${FICTION_HTTP_ERROR_BEGIN}<h1 style='font-size:48px'>${1}</h1><h2>${@:2}</h2>${FICTION_HTTP_ERROR_END}"
}

clean() {
  echo -e "\nStopping the server..."
  [[ -n "$serverTmpDir" && -d "$serverTmpDir" ]] && rm -rf "$serverTmpDir"
  exit
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
 # echo "renamed $1 to $2 $(declare -f $2)" >&2
  unset -f "$1";
}



parsePost() {
  if [[ "${FictionRequest[method]}" =~ "POST"|"PATCH"|"PUT" ]] && ((${FictionRequestHeaders['content-length']:=0} > 0)); then
  local entry
  if [[ "${FictionRequestHeaders["content-type"]}" == "application/x-www-form-urlencoded" ]]; then
    IFS='&' read -rN "${FictionRequestHeaders["Content-Length"]}" -a data
    for entry in "${data[@]}"; do
    entry="${entry%%$'\r'}"
    POST["${entry%%=*}"]="${entry#*:}"
    done
  elif [[ "${FictionRequestHeaders["content-type"]}" == "application/json" ]]; then
    read -N "${FictionRequestHeaders["content-length"]}" data
    eval "$(json_to_arr "${data%%$'\r'}" POST)"
  else
    read -rN "${FictionRequestHeaders["content-length"]}" data
    POST["raw"]="${data%%$'\r'}"
  fi
  unset entry
  fi
}




function FictionRequestHandler() {
  [[ "${FictionRequest[path]}" =~ ".."|"~" ]] && fiction.404
  [ "${FictionRequest[path]::2}" == "//" ] && FictionRequest[path]="${FictionRequest[path]:1}";
  [ "${FictionRequest[path]::1}" != "/" ] && FictionRequest[path]="/${FictionRequest[path]}";
  [[ "${FictionRequest[method]}" == 'POST' && -n "${FictionRequestHeaders['fiction-action']}" ]] && FictionRequest[path]="/${FictionRequestHeaders['fiction-action']}";
  if [ -f "$serverTmpDir/.routes" ]; then
    local route func route1 func1 m=false ou;
    #route1=$(echo "${FictionRequest[path]}" | sha256sum);
    routes=$(__d "$serverTmpDir/.routes");
    ou=$(echo "$routes" | grep "${FictionRequest[path]}");
    ou2=$(echo "$routes" | grep "dynamic");
    if [[ "$ou" ]]; then
      read type filetype route func <<< "$ou";
      read func funcargs <<< "$func";
      FICTION_ROUTE="${FictionRequest[path]}";
      if [[ $type == cgi ]]; then
        local headers=;
        (
        SERVER_SOFTWARE="Fiction ${Fiction[version]}" \
        REQUEST_METHOD="${FictionRequest[method]}" \
        REMOTE_ADDR="$REMOTE_ADDR" \
        FICTION_ROUTE="${FictionRequest[path]}" \
        FictionRequest[path]="${FictionRequest[path]}" \
        CONTENT_LENGTH="${FictionRequestHeaders['content-length']}" \
        SCRIPT_NAME="$func" \
        HTTPS="${Fiction[https]}" \
        SCRIPT_FILENAME="$(basename -f "$func")" \
        HTTP_USER_AGENT="${FictionRequestHeaders['user-agent']}" \
        HTTP_FictionRequestCookie="${FictionRequestHeaders['cookie']}" \
        $func;
        )
      else
        parsePost
        [[ "$func" == 'echo' ]] && $func ${funcargs//\"/\\\"} || $func "${funcargs//\"/\\\"}";
      fi
    else
      if [[ -n "$ou2" ]]; then
        while read route; do
          read type contenttype route func <<< "$route"
          local regex=$(echo "$route" | sed -e 's#\[[^]]*\]#([^/]+)#g')
          regex="${regex%/}/?"
          [[ "${FictionRequest[path]}" =~ $regex ]] || continue
          local slugs=$(echo "$route" | grep -oP '\[\K[^]]+(?=\])' | tr '\n' ' ' | sed 's/,$//')
          slugs="${slugs% }" 
          read _ $slugs <<< "${BASH_REMATCH[@]}"
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
  time1=$(date +%s%3N)
  FictionRequest[time]="$time1"
  local REQUEST_METHOD REQUEST_PATH HTTP_VERSION QUERY_STRING
  read -r REQUEST_METHOD REQUEST_PATH HTTP_VERSION
  HTTP_VERSION="${HTTP_VERSION%%$'\r'}"
  [[ "$HTTP_VERSION" =~ HTTP/[0-9]\.?[0-9]? ]] && HTTP_VERSION="${BASH_REMATCH[0]}"
  [[ -z "$REQUEST_METHOD" || -z "$REQUEST_PATH" ]] && return
  FictionRequest[method]="$REQUEST_METHOD"
  FictionRequest[path]="$REQUEST_PATH"
  FictionRequest[version]="$HTTP_VERSION"
  FictionRequest[addr]="$REMOTE_ADDR"
  local line _h
  while read -r line; do
    line="${line%%$'\r'}"
    [[ -z "$line" ]] && break
    _h="${line%%:*}"
    FictionRequestHeaders["${_h,,}"]="${line#*: }"
  done
  unset line _h
  local entry
  IFS='?' read -r REQUEST_PATH get <<<"$REQUEST_PATH"
  get="$(urldecode "$get")"
  IFS='#' read -r REQUEST_PATH _ <<<"$REQUEST_PATH"
  QUERY_STRING="$get"
  IFS='&' read -ra data <<<"$get"
  for entry in "${data[@]}"; do
    FictionRequestQuery["${entry%%=*}"]="${entry#*=}"
  done
  entry=''
  local -a cookie
  local key value
  IFS=';' read -ra cookie <<<"${FictionRequestHeaders["cookie"]}"
  [ -n "${FictionRequestHeaders["Cookie"]}" ] && ((${#cookie[@]} < 1 )) && cookie+=( ${FictionRequestHeaders["cookie"]//;} )
  for entry in ${cookie[@]}; do
    IFS='=' read -r key value <<<"$entry"
    [[ "$key" ]] && FictionRequestCookie["$key"]="${value}"
  done
  unset entry cookie key value

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
      eval $(json_to_arr "${data%%$'\r'}" FictionRequestData)
    else
      read -rN "${FictionRequestHeaders["content-length"]}" data
      FictionRequestData["raw"]="${data%%$'\r'}"
    fi
    unset entry
  fi
  filename="$serverTmpDir/output_$RANDOM"
  [ -f "$filename" ] && rm "$filename"
  FictionRequestHandler >"$filename"
  [ -z "${FictionResponse["status"]}" ] && FictionResponse["status"]="${statuscode:=200}"
  printf '%s %s\n' "HTTP/1.1" "${FictionResponse["status"]}"
  local routetype="$type"

  # printf '%s\n' "$(<"$filename")"
   # cat "$filename" >&2
  if [[ -z "$filetype" || "$filetype" == "auto" ]]; then
    local _ char type="$(file --mime "$filename")"
    IFS=' ' read _ type char <<<"$type"
    which file 2>&1 >/dev/null && FictionResponseHeaders["content-type"]="${type//;/}"
    unset _ type char
  else
    FictionResponseHeaders["content-type"]="${filetype}"
  fi

  if [[ "${FictionResponseHeaders["content-type"]}" =~ html && "$routetype" != cgi ]]; then
    local isdoctype=false ishtml=false isbody=false iscbody=false ishead=false ischtml=false ischead=false
    local output=$(<"$filename")
    if [[ "${output::6}" != '<html>' && "${output::15}" != '<!DOCTYPE html>' ]]; then
  #local csrf=$(sessionGet "$SESSION_ID")
    (
      cat << EOF 
<!DOCTYPE html>
<html>
  <head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  ${FictionResponse[head]}$FICTION_META
EOF
    "${Fiction[include_dom]:-false}" && echo "<script>$(<"$dom_path")</script>";
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
  ) > "$filename";
  fi
  fi
  read size filename < <(wc -c "$filename")
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
  unset routetype
  case "${FictionResponse[status]}" in
    2[0-9][0-9]) local status="${_green}${FictionResponse[status]}${_nc}" ;;
    3[0-9][0-9]) local status="${_yellow}${FictionResponse[status]}${_nc}" ;;
    4[0-9][0-9]|5[0-9][0-9]) local status="${_red}${FictionResponse[status]}${_nc}" ;;
    *) status="${FictionResponse[status]}"
  esac
  echo "[$(date +"%d/%m/%y %H:%M:%S")] ${Fiction[expose_addr]:+$REMOTE_ADDR} ${FictionRequest[method]} ${FictionRequest[path]} $status $(($(date +%s%3N)-time1))ms" >&2
  unset status
  exit
}

# HelperFns

function fiction.addServerAction() {
  [ -z "$1" ] && return
  local path="/__server-action_$(echo "$1" | sha256sum)"
  local path2="$(sha256sum <<< "${path::-3}")"
  [[ ! "$(__d "$serverTmpDir/.routes")" =~ ${path2::-3} ]] && fiction.serve "${path::-3}" "$1" "" api >&2
  [[ $? == 0 ]] && printf "%s" "serverAction('${path::-3}')" || return
  unset path json
}


function fiction.addMeta() {
  FictionResponse[head]+="$@"$'\n'
}

function fiction.header.set() {
  [[ -z "$1" || -z "$2" ]] && return
  FictionResponseHeaders["$1"]="$2"
}

function fiction.session() {
  [ ! -f "$serverTmpDir/.sessions" ] && { echo ""; return; }
  local s c s1 c1 m=false
  s1=$(echo "$1" | sha256sum)
  ou=$(__d "$serverTmpDir/.sessions" | grep "${s1::-3}")
  [ -n "$ou" ] && IFS=' ' read s c <<< "$ou" || { echo ""; return; }
  [[ "${s1::-3}" == "$s" ]] || { echo ""; return; }
  c1=$(base64 -d <<< "$c")
}

function fiction.response.cookie.set() {
  FictionResponseCookie+=("$1")
}

function fiction.session.set() {
  if [ ! -f "$serverTmpDir/.sessions" ]; then
  : >"$serverTmpDir/.sessions"
  local session="$(generate_session_id)"
  local ssession=$(echo "$session" | sha256sum)
  local tok="$(generate_csrf_token | base64 -w 0)"
  __e "${ssession::-3} $tok" "$serverTmpDir/.sessions"
  fiction.cookie.set "session_id=${session}; HttpOnly; max-age=${1:-10000}"
  SESSION_ID="${session}"
  unset session tok
  else
  local ou="$(__d "$serverTmpDir/.sessions")"
  local session="$(generate_session_id)"
  local ssession=$(echo "$session" | sha256sum)
  local tok="$(generate_csrf_token | base64 -w 0)"
   ou+=$'\n'"${ssession::-3} $tok"
  __e "$ou" "$serverTmpDir/.sessions"
  fiction.cookie.set "session_id=${session}; HttpOnly; max-age=${1:-10000}"
  unset ou session tok
  fi
}



function fiction.request.getQuery() {
  [ -z "$1" ] && return
  IFS="=" read -r _ val <<<"${GET["$1"]}"
  echo "$val"
}

function fiction.request.getSlug() {
  [ -z "$1" ] && return 1
  echo "${!1}"
}

function fiction.getRoute() {
  echo "${Fiction[route]}"
}

fiction.respond() {
  local output;
  [[ -z "$1" ]] && error "At least one argument expected" >&2 && return 1
  FictionResponse["status"]="$1"
  [[ -z "$2" ]] && while read chunk; do output+="$chunk"$'\n'; done || local output="$2"
  echo "$output"
}

function fiction.serve() {
  # fiction.serve <from> <to:fn> <as> <type?> <headers?>
  [[ -z "$1" || -z "$2" ]] && return 1
  mktmpDir
  local type="${4:-static}"
  if [[ "$FICTION_BUILD" ]]; then
  [[ "$3" == text/html ]] || return
  fi
  [[ "${FictionRoute["$1"]}" ]] && error "Dublicate of existing route: $1 -> ${FictionRoute[$1]}" && return 1 || FictionRoute["$1"]="$2"
  case "$type" in
    api | cgi)
      [[ $type == cgi ]] && [ ! -x "$2" ] && error "$2 is not an executable. Check if the file exists and has executable permission" && return 1
      funcname="$2";
      route="$1"
    ;;
    static | dynamic | dynamic-api)
      route="$1";
      funcname="$(uuidgen)";
      declare -F "$2" > /dev/null && rename_fn "$2" "$funcname" || eval "$funcname() { ${2%;}; }"
    ;;
  esac
  if [ ! -f "$serverTmpDir/.routes" ]; then
  : >"$serverTmpDir/.routes"
  __e "$type ${3:-auto} $route $funcname" "$serverTmpDir/.routes"
  unset ou route funcname
  else
  local ou="$(__d "$serverTmpDir/.routes")"
  rename_fn "$2" "$funcname"
  ou+=$'\n'"$type ${3:-auto} $route $funcname"
  __e "$ou" "$serverTmpDir/.routes"
  unset ou route funcname
  fi
  echo "[${_white}+${_nc}] Added ${type} route: from ${_bold}'$1'${_nc} to ${_bold}'$2'${_nc} ${3:+as '$3'}"
}

fiction.404() {
#  INCLUDE_DOM=false
#  Fiction[include_lucide]=false
  fiction.header.set "server" "Fiction/${Fiction[version]}"
  fiction.respond 404 <<- EOF
  <!DOCTYPE html>
  <html style='font-family:sans-serif;background-color:black;color:white;'>
    <meta>
      <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
      <title>Not found - Fiction</title>
    </meta>
    <body class="w-full h-full">
      <div class="mx-auto mt-24 text-center">
        <h1 class="text-7xl font-bold">404</h1>
        The route is... fictional?
      </div>
      <div>
    </body>
  </html>
EOF
  return
}

fiction.500() {
  fiction.header.set "server" "Fiction/${Fiction[version]}"
  fiction.respond 500 <<- EOF
  <!DOCTYPE html>
  <html style='font-family:sans-serif;background-color:black;color:white;'>
    <meta>
      <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
      <title>Server Error - Fiction</title>
    </meta>
    <body class="w-full h-full">
      <div class="mx-auto mt-24 text-center">
        <h1 class="text-7xl font-bold">500</h1>
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
  local ROUTEFN="FR$(uuidgen)";
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
  fiction.serve "${ROUTEPATH}" "${ROUTEFN}" "${3:-$(file --mime-type -b "${1}")}"
}

function fiction.serveDir() {
  local ROUTE_APPEND="$2";
  local download="$3";
  [[ "${download:-true}" == true ]] && local type=application/x-octet-stream;
  if [[ -n "$ROUTE_APPEND" ]] && [[ "${ROUTE_APPEND: -1}" == "/" ]]; then
    ROUTE_APPEND="${ROUTE_APPEND:0:0-1}";
  fi
  if [ -d "$1" ]; then
    [[ "${4:-true}" == true ]] && fiction.serve "${ROUTE_APPEND}" "tree -H '$ROUTE_APPEND' -L 1 '$1'" "text/html";
    test -e "$1/"* > /dev/null 2>&1 && for item in ${1}/*;
    do
      if [ -d "$item" ]; then
        [[ "${5:-true}" == true ]] && fiction.serveDir "${item}" "${ROUTE_APPEND}/${item##*/}" > /dev/null;
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
  if [[ -z "${FictionRoute['/favicon.svg']}" ]]; then 
    declare -A _hh=([cache-control]="public,max-age=86400" [age]=0)
    fiction.serveFile "${FICTION_PATH}favicon.svg" "/favicon.ico" "" "_hh" >/dev/null
  fi
  [[ "$FICTION_BUILD" ]] && return
  local origaddress="$1";
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
  unset address port
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
  echo -e "\nStarting Fiction (${_green}${Fiction[version]}${_nc})"
  [[ "${Fiction[include_wasm]}" == true && "${Fiction[https]:=false}" == false ]] && error "Running the website with WASM included on HTTP. Modern browsers will not allow WASM initialization from HTTP origin. In case it's a development server, consider using ncat for running a temporary HTTPS server." && return 1
  mktmpDir
  case "${Fiction[core]}" in
    bash)
      if "${Fiction[https]:=false}"; then
      echo "HTTPS isn't available in development core. Use ncat or socat for HTTPS server" 1>&2;
      exit 1;
      else
      [ ! -f "${FictionModule[accept]}" ] && error "\`accept\` is not found in ${Fiction[path]}" && return 1;
      enable -f "${FictionModule[accept]}" accept;
      [[ "${Fiction[bind_port]}" = 80 ]] && echo -e "\nServer address: http://${Fiction[bind_address]} (single connection mode)" || echo -e "\nServer address: http://${Fiction[bind_address]}:${Fiction[bind_port]} (single connection mode)";
      while true; do
        (
          accept -b "${Fiction[bind_address]}" -r REMOTE_ADDR "${Fiction[bind_port]}";
          if [[ -n "$ACCEPT_FD" ]]; then
            parseAndPrint <&${ACCEPT_FD} >&${ACCEPT_FD};
            exec {ACCEPT_FD}>&-;
          fi
        );
      done
      fi
    ;;
    nc | netcat | ncat | socat)

      ( 
        echo "#!/bin/bash"
        echo "FICTION_PATH='$FICTION_PATH'"
        declare -A
        unset -f fiction.server @cache @prerender
        [[ "${FictionModule[bashx]}" ]] && unset -f @import bashx mktmpDir @render_type @wrapper _render _conditionalRender
        declare | \
        grep -vE '(^Fiction*=|^chunk=|^newblock=|^out1=|^GPG|^SHELL|^SESSION_|^OS|^KDE_*|^GTK*|^XDG*|^XKB*|^PAM*|^KONSOLE*|^SSH_*|^QT_*|^PWD|^OLDPWD|^TERM|^HOME|^USER|^PATH|^BASH_*|^BASHOPTS|^EUID|^PPID|^SHELLOPTS|^UID)'
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
      ) >>"$serverTmpDir/worker.sh";
      chmod +x "$serverTmpDir/worker.sh";
      trap clean EXIT;
      echo -n "Server address: ";
      case "${Fiction[core]:-socat}" in
      socat)
        which socat >/dev/null || { error "cannot find socat binary" && return 1; }
        if "${Fiction[https]:=false}"; then
          [[ "${Fiction[bind_port]}" = 443 ]] && echo -n "https://${Fiction[bind_address]}" || echo -n "https://${Fiction[bind_address]}:${Fiction[bind_port]}";
          echo " (forking mode)";
          exec -a "fiction" socat openssl-listen:"${Fiction[bind_port]}",bind="$BIND_ADDRESS",verify=0,${Fiction[ssl_cert]:+cert="${Fiction[ssl_cert]}",}${Fiction[ssl_key]:+key="${Fiction[ssl_key]}",}reuseaddr,fork SYSTEM:"$serverTmpDir/job.sh";
        else
          [[ "${Fiction[bind_port]}" = 80 ]] && echo -n "http://${Fiction[bind_address]}" || echo -n "http://${Fiction[bind_address]}:${Fiction[bind_port]}";
          echo " (forking mode)";
          exec -a "fiction" socat TCP-LISTEN:${Fiction[bind_port]},bind="$BIND_ADDRESS",reuseaddr,fork EXEC:''"$serverTmpDir"'/worker.sh';
        fi
      ;;
      ncat)
        which ncat >/dev/null || { error "cannot find ncat binary" && return 1; }
        if "${Fiction[https]:=false}"; then
          [[ "${Fiction[bind_port]}" = 443 ]] && echo -n "https://${Fiction[bind_address]}" || echo -n "https://${Fiction[bind_address]}:${Fiction[bind_port]}";
          echo " (forking mode)";
          ( exec -a "fiction" ncat -klp "${Fiction[bind_port]}" -c "$serverTmpDir/worker.sh" --ssl ${Fiction[ssl_cert]:+--ssl-cert "${Fiction[ssl_cert]}"} ${Fiction[ssl_key]:+--ssl-key "${Fiction[ssl_key]}"}; )
        else
          [[ "${Fiction[bind_port]}" = 80 ]] && echo -n "http://${Fiction[bind_address]}" || echo -n "http://${Fiction[bind_address]}:${Fiction[bind_port]}";
          echo " (forking mode)";
          ( exec -a "fiction" ncat -klp "${Fiction[bind_port]}" -c "$serverTmpDir/worker.sh"; )
          fi
      ;;
      nc | netcat)
        nc --version 2> 1 > /dev/null && nc_path="nc.traditional" || nc_path="nc";
        which "$nc_path" >/dev/null || { error "cannot find netcat binary" && return 1; }
        if "${Fiction[https]:=false}"; then
          error "Fiction[https] is not supported in legacy netcat mode" 1>&2
        else
          [[ "${Fiction[bind_port]}" = 80 ]] && echo -n "http://${Fiction[bind_address]}" || echo -n "http://${Fiction[bind_address]}:${Fiction[bind_port]}";
          echo " (forking mode)";
          while true; do
            (
              exec -a "fiction" $nc_path -vklp "${Fiction[bind_port]}" -e "$serverTmpDir/worker.sh";
              (($? != 0)) && break
            )
          done
        fi
      ;;
      esac
    ;;
  esac
}

function declare_objects() {
  [[ ${Fiction[routes]} != FictionRoute ]] && unset FictionRoute && declare -gn FictionRoute="${Fiction[routes]}"
  [[ ${Fiction[modules]} != FictionModule ]] && unset FictionModule && declare -gn FictionModule="${Fiction[modules]}"
  [[ ${Fiction[response]} != FictionResponse ]] && unset FictionResponse && declare -gn FictionResponse="${Fiction[responses]}"
  [[ ${Fiction[request]} != FictionRequest ]] && unset FictionRequest && declare -gn FictionRequest="${Fiction[requests]}"
  }
declare_objects
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
    fi
  ;;
  bashx)
    [[ -v FictionModule[bashx] ]] && continue
    if [[ -f "$file/bashx" ]]; then
    FictionModule[bashx]="$file/bashx"
    source "$file/bashx"
    else
    error "cannot load bashx ($file/bashx)"
    fi
  ;;
  bash-wasm)
    [[ -v FictionModule[wasm] ]] && continue
    if [[ -f "$file/index.sh" ]]; then
    FictionModule[wasm]="$file"
    source "$file/index.sh"
    else
     error "cannot load WASM module ($file/index.sh)"
    fi
  ;;
  esac
done

if ! (return 0 2>/dev/null); then
  case "$1" in
  run)
    if ! declare -F bashx >/dev/null 2>&1; then
    if [ -f "${FictionModule[bashx]}" ]; then
      BASHX_NESTED=true
      source "${FictionModule[bashx]}"
    else
      error "cannot load bashx (${FictionModule[bashx]})" >&2
      exit 1
    fi
    fi
    [[ "$2" ]] && Fiction[default_index]="$2"
    BASHX_VERBOSE=true
    bashx "${Fiction[default_index]}"
  ;;
  build)
    echo "Initializing build..."
    time=$(date +%s%3N)
    if ! declare -F bashx >/dev/null 2>&1; then
    if [ -f "${FictionModule[bashx]}" ]; then
      BASHX_NESTED=true
      source "${FictionModule[bashx]}"
    else
      error "cannot load bashx (${FictionModule[bashx]})"
      exit 1
    fi
    fi
    FICTION_BUILD=true
    [[ "$2" ]] && Fiction[default_index]="$2"
    [[ "$3" ]] && target_dir="$3"
    BASHX_VERBOSE=true
    bashx "${Fiction[default_index]}"
    [[ $? > 0 ]] && exit
    while read route; do
    read type filetype route func <<< "$route";
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
  ;;
  version)
    cat << EOF
Fiction ${Fiction[version]}
Copyright (C) Tirito6626, notnulldaemon 2025
EOF
  ;;
  *)
    error "Invalid action: $1"
    cat << EOF
Usage: $0 [action] [arguments]

Available actions:
  run   [file?]            Start the server using <file> with preloaded Fiction (index.shx default)
  build [file?] [target?]  Build the routes defined into <file> into <target> directory (fiction_compiled default)
EOF
    exit 1
  ;;
  esac
else
  if [[ "$FICTION_NESTED" != true ]]; then
    if [[ "${BASH_SOURCE[-1]}" =~ .shx|.bashx ]]; then
      if ! declare -F bashx >/dev/null 2>&1; then
        if [ -f "${FictionModule[bashx]}" ]; then
          FICTION_NESTED=true
          source "${FictionModule[bashx]}"
          bashx "${BASH_SOURCE[-1]}"
          exit
        else
          error "cannot load bashx (${FictionModule[bashx]})"
          exit 1
        fi
      else 
        FICTION_NESTED=true
        bashx "${BASH_SOURCE[-1]}"
        exit
      fi
    fi
  fi
fi
