#!/bin/bash
# The Fiction(R) Library!
# Http Server
FICTION_HTTP_ERROR_BEGIN="<html style='font-family:sans-serif;background-color:#212121;color:white;'><title>Error</title><center>"
FICTION_HTTP_ERROR_END="<hr><p>Fiction Web Server</h1></center></html>"
FICTION_PATH=$(readlink -f "${BASH_SOURCE[0]:-$0}")
FICTION_PATH="${FICTION_PATH//fiction.so.sh}"
bashx_path="$FICTION_PATH/modules/bashx"
default_index="index.shx"
FICTION_META=""
workerargs=""
core=""
_green="$(tput setaf 2)"
_red="$(tput setaf 1)"
_white="$(tput setaf 255)"
_bold="$(tput bold)"
_nc="$(tput sgr 0)"
FICTION_VERSION="v1.0.0-prerelease"
encode_routes="false"

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
    ! pidof fiction >/dev/null && [ -d "$FICTION_PATH/.fiction" ] && rm -rf $FICTION_PATH/.fiction/* 2>1 >/dev/null
    serverTmpDir="$FICTION_PATH/.fiction/tmp_$(openssl rand -hex 16)"
    mkdir -p "$serverTmpDir"
    #echo $?
    if [[ $? > 0 ]]; then
      serverTmpDir="/tmp/.fiction/tmp_$(openssl rand -hex 16)"
      mkdir -p "$serverTmpDir"
    fi
  fi
}

function sendAction() {
  [[ "${2::2}" == '{"' ]] && local json="{\"type\":\"$1\",${3:+\"id\":\"$3\",}\"data\":$2 }" || local json="{\"type\":\"$1\",${3:+\"id\":\"$3\",}\"data\":\"$2\" }"
  echo "${json}"
}

function addMeta() {
  FICTION_HEAD+="$@"$'\n'
}

function setHeader() {
  [[ -z "$1" || -z "$2" ]]
  HTTP_RESPONSE_HEADERS["$1"]="$2"
}

function error() {
  [[ ${#FUNCNAME[@]} > 1 ]] && echo -n "(${FUNCNAME[1]}) "
  echo "${_red}Error:${_nc} ${@}" >&2
}

function addServerAction() {
  [ -z "$1" ] && return 
  if [[ "$4" ]]; then 
    for opt in "$4"; do 
      IFS='=' read key value <<< "$opt"
      case "$key" in 
        "csrf") _csrf="$value" ;;
      esac
    done
  fi
  local path="/__server-action_$(echo "$1" | sha256sum)"
  local path2="$(sha256sum <<< "${path::-3}")"
  [[ ! "$(__d "$serverTmpDir/.routes")" =~ ${path2::-3} ]] && FictionServePath "${path::-3}" "$1" "" api >&2
  [[ $? == 0 ]] && printf "%s" "serverAction('${path::-3}')" || return 
  unset path json
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
declare -A FictionRoute
declare -a FictionDynamicRoute
declare -A FictionRouteContentType
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
    [500]="500 Internal Server Error"
  )

  HTTP_RESPONSE_HEADERS["status"]="${status_code[${1:-200}]}"
}

buildResponse() {
  filename="$serverTmpDir/output_$RANDOM"
  [ -f "$filename" ] && rm "$filename"
  FictionRequestHandler >"$filename"
  [ -z "${HTTP_RESPONSE_HEADERS["status"]}" ] && httpSendStatus "${statuscode:=200}"
  printf '%s %s\n' "HTTP/1.1" "${HTTP_RESPONSE_HEADERS["status"]}"
  status="${HTTP_RESPONSE_HEADERS["status"]}"
  routetype="$type"
  unset 'HTTP_RESPONSE_HEADERS["status"]'

  # printf '%s\n' "$(<"$filename")"
     # cat "$filename" >&2 
  if [[ -z "$filetype" || "$filetype" == "auto" ]]; then
    local _ char type="$(file --mime "$filename")"
    IFS=' ' read _ type char <<<"$type"
    which file 2>&1 >/dev/null && HTTP_RESPONSE_HEADERS["content-type"]="${type//;/}"
    unset _ type char
  else
    HTTP_RESPONSE_HEADERS["content-type"]="${filetype}"
  fi
  if [[ "${HTTP_RESPONSE_HEADERS["content-type"]}" =~ html && "$routetype" != cgi ]]; then 
    local isdoctype=false ishtml=false isbody=false iscbody=false ishead=false ischtml=false ischead=false
    local output=$(cat "$filename")
    if [[ "${output::6}" != '<html>' && "${output::15}" != '<!DOCTYPE html>' ]]; then
    #local csrf=$(sessionGet "$SESSION_ID")
    #
      cat << EOF > "$filename" 
<!DOCTYPE html>
<html> 
  <head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    $FICTION_HEAD
    $(
      "${INCLUDE_DOM:-true}" && echo "<script>$(cat "$FICTION_PATH/dom.js")</script>";
      "${INCLUDE_TAILWINDCSS:-true}" && echo '<script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>';
      "${INCLUDE_LUCIDE:-true}" && echo '<script src="https://unpkg.com/lucide@latest"></script>';
      echo '</head>';
      [[ "${output::5}" == \<body ]] && echo "$output" || echo "<body>$output</body>";
      "${INCLUDE_LUCIDE:=true}" && echo '<script>lucide.createIcons();</script>'
     )
</html>
EOF
    fi
  fi

  read size filename < <(wc -c "$filename")
  HTTP_RESPONSE_HEADERS["content-length"]="${size:=0}"
  if [[ "$routetype" != "cgi" ]]; then
    for key in "${!HTTP_RESPONSE_HEADERS[@]}"; do
      printf '%s: %s\n' "${key,,}" "${HTTP_RESPONSE_HEADERS[$key]}"
    done
    for value in "${cookie_to_send[@]}"; do
      printf 'Set-Cookie: %s\n' "$value"
    done
    printf "\n"
  fi 
  cat "$filename"
  printf "\n"
  rm "$filename"
  unset routetype
}
__x4gT9q6=( "$(openssl rand -hex 32)" "$(openssl rand -hex 16)" );

respond() {
  [[ -z "$1" || -z "$2" ]] && echo "$FUNCNAME: 2 arguments expected" >&2 && return 1
  HTTP_RESPONSE_HEADERS["status"]="$1"
  echo "$2"
}
parseAndPrint() {
  time1=$(date +%s%3N)
  verbose=true
  local REQUEST_METHOD REQUEST_PATH HTTP_VERSION QUERY_STRING
  local -A HTTP_HEADERS
  declare -Ag POST 
  declare -Ag GET
  local -A HTTP_RESPONSE_HEADERS
  local -A COOKIE
  local -A SESSIONS
  local -a cookie_to_send
  
  read -r REQUEST_METHOD REQUEST_PATH HTTP_VERSION
  HTTP_VERSION="${HTTP_VERSION%%$'\r'}"
  [[ "$HTTP_VERSION" =~ HTTP/[0-9]\.?[0-9]? ]] && HTTP_VERSION="${BASH_REMATCH[0]}"
  [[ -z "$REQUEST_METHOD" || -z "$REQUEST_PATH" ]] && return

  local line _h
  while read -r line; do
    line="${line%%$'\r'}"
    [[ -z "$line" ]] && break
    _h="${line%%:*}"
    HTTP_HEADERS["${_h,,}"]="${line#*: }"
  done
  unset line _h

  local entry
  IFS='?' read -r REQUEST_PATH get <<<"$REQUEST_PATH"
  get="$(urldecode "$get")"
  IFS='#' read -r REQUEST_PATH _ <<<"$REQUEST_PATH"
  QUERY_STRING="$get"
  IFS='&' read -ra data <<<"$get"
  for entry in "${data[@]}"; do
    GET["${entry%%=*}"]="${entry#*=}"
  done
  REQUEST_PATH="$(dirname "$REQUEST_PATH")/$(basename "$REQUEST_PATH")"
  REQUEST_PATH="${REQUEST_PATH#/}"

  entry=''

  local -a cookie
  local key value
  IFS=';' read -ra cookie <<<"${HTTP_HEADERS["cookie"]}"
  [ -n "${HTTP_HEADERS["Cookie"]}" ] && ((${#cookie[@]} < 1 )) && cookie+=( ${HTTP_HEADERS["cookie"]//;} )
  for entry in ${cookie[@]}; do
    IFS='=' read -r key value <<<"$entry"
    [[ "$key" ]] && COOKIE["$key"]="${value}"
  done
  unset entry cookie key value

  if [[ "$REQUEST_METHOD" == "POST" ]] && ((${HTTP_HEADERS['content-length']:=0} > 0)); then
    local entry
    if [[ "${HTTP_HEADERS["content-type"]}" == "application/x-www-form-urlencoded" ]]; then
      IFS='&' read -rN "${HTTP_HEADERS["Content-Length"]}" -a data
      for entry in "${data[@]}"; do
        entry="${entry%%$'\r'}"
        POST["${entry%%=*}"]="${entry#*:}"
      done
    elif [[ "${HTTP_HEADERS["content-type"]}" == "application/json" ]]; then 
      read -N "${HTTP_HEADERS["content-length"]}" data
      eval $(json_to_arr "${data%%$'\r'}" POST) 
    else
      read -rN "${HTTP_HEADERS["content-length"]}" data
      POST["raw"]="${data%%$'\r'}"
    fi
    unset entry
  fi
  
  buildResponse
  unset POST GET
  "${verbose:=false}" && echo "[$(date)] $HTTP_VERSION $REQUEST_METHOD $REQUEST_PATH $status $(($(date +%s%3N)-time1))ms" >&2
  unset HTTP_VERSION REQUEST_METHOD REQUEST_PATH status
}


__e() {
  "$encode_routes" && openssl enc -aes-256-cbc -K "${__x4gT9q6[0]}" -iv "${__x4gT9q6[1]}" -out "$2" <<< "$1" || echo "$1" > "$2"
}

__d() {
  "$encode_routes" &&   openssl enc -d -aes-256-cbc -K "${__x4gT9q6[0]}" -iv "${__x4gT9q6[1]}" -in "$1" || cat "$1"
}


sessionGet() {
  [ ! -f "$serverTmpDir/.sessions" ] && { echo ""; return; }
  local s c s1 c1 m=false
  s1=$(echo "$1" | sha256sum)
  ou=$(__d "$serverTmpDir/.sessions" | grep "${s1::-3}")
  [ -n "$ou" ] && IFS=' ' read s c <<< "$ou" || { echo ""; return; }
  [[ "${s1::-3}" == "$s" ]] || { echo ""; return; }
  c1=$(base64 -d <<< "$c")
}

cookieSet() {
  cookie_to_send+=("$1")
}

sessionSet() {
  if [ ! -f "$serverTmpDir/.sessions" ]; then
    : >"$serverTmpDir/.sessions"
    local session="$(generate_session_id)" 
    local ssession=$(echo "$session" | sha256sum)
    local tok="$(generate_csrf_token | base64 -w 0)"
    __e "${ssession::-3} $tok" "$serverTmpDir/.sessions"
    cookieSet "session_id=${session}; HttpOnly; max-age=5000"
    SESSION_ID="${session}"
    unset session tok
  else 
    local ou="$(__d "$serverTmpDir/.sessions")"
    local session="$(generate_session_id)" 
    local ssession=$(echo "$session" | sha256sum)
    local tok="$(generate_csrf_token | base64 -w 0)"
     ou+=$'\n'"${ssession::-3} $tok"
    __e "$ou" "$serverTmpDir/.sessions"
    cookieSet "session_id=${session}; HttpOnly; max-age=5000"
    unset ou session tok
  fi
}


sendError() {
  set -- $1
  printf '%s\n' "${FICTION_HTTP_ERROR_BEGIN}<h1 style='font-size:48px'>${1}</h1><h2>${@:2}</h2>${FICTION_HTTP_ERROR_END}"
}


clean() {
  echo "Stopping the server..."
  [[ -n "$serverTmpDir" && -d "$serverTmpDir" ]] && rm -rf "$serverTmpDir"
  exit
}

# --- END OF https://github.com/dzove855/Bash-web-server/ ---
function getQuery() {
  [ -z "$1" ] && return
  IFS="=" read -r _ val <<<"${GET["$1"]}"
  echo "$val"
}

function getSlug() {
  [ -z "$1" ] && return 1
  local var="FICTION_SLUG_$1"
  echo "${!var}"
  unset var
}

function getRoute() {
  echo "$FICTION_ROUTE"
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

function FictionRequestHandler() { 
    case "$REQUEST_PATH" in 
        *".."* | *"~"*)
            show_404
        ;;
    esac;
    [ "${REQUEST_PATH::2}" == "//" ] && REQUEST_PATH="${REQUEST_PATH:1}";
    [ "${REQUEST_PATH::1}" != "/" ] && REQUEST_PATH="/${REQUEST_PATH}";
    [[ "$REQUEST_METHOD" == 'POST' && -n "${HTTP_HEADERS['fiction-action']}" ]] && REQUEST_PATH="/${HTTP_HEADERS['fiction-action']}";
    if [ -f "$serverTmpDir/.routes" ]; then
        local route func route1 func1 m=false ou;
        #route1=$(echo "$REQUEST_PATH" | sha256sum);
        routes=$(__d "$serverTmpDir/.routes");
        ou=$(echo "$routes" | grep "$REQUEST_PATH");
        ou2=$(echo "$routes" | grep "dynamic");
        if [[ "$ou" ]]; then
            read type filetype route func <<< "$ou";
            read func funcargs <<< "$func";
            FICTION_ROUTE="$REQUEST_PATH";
            if [[ $type == cgi ]]; then
                local headers=;
                SERVER_SOFTWARE="Fiction $FICTION_VERSION" REQUEST_METHOD="$REQUEST_METHOD" REMOTE_ADDR="$REMOTE_ADDR" FICTION_ROUTE="$REQUEST_PATH" REQUEST_PATH="$REQUEST_PATH" SCRIPT_FILENAME="$func" HTTP_USER_AGENT="${HTTP_HEADERS['user-agent']}" $func;
            else
                [[ "$func" == 'echo' ]] && $func ${funcargs//\"/\\\"} || $func "${funcargs//\"/\\\"}";
            fi
        else
            if [[ -n "$ou2" ]]; then
                local matching_slugs=0;
                IFS='/' read -ra path_keys <<< "${REQUEST_PATH#\/}";
                i=0;
                route=$(echo "$ou2" | grep "${path_keys[0]}");
                if [[ -n "$route" ]]; then
                    IFS=' ' read _ filetype route func funcargs <<< "$route";
                    IFS='/' read -ra route_keys <<< "${route#\/}";
                    IFS='/' read -ra path_keys <<< "${REQUEST_PATH#\/}";
                    for subroute in ${path_keys[@]};
                    do
                        if [[ ${route_keys[$i]} =~ '[' ]]; then
                            local slug="${route_keys[$i]#\[}";
                            slug="${slug%\]}";
                            printf -v "FICTION_SLUG_$slug" "%s" "$subroute";
                            ((matching_slugs++));
                        else
                            [[ "$subroute" == "${route_keys[$i]}" ]] || break;
                        fi
                        ((i++));
                    done
                    if ((matching_slugs > 0)); then
                        read func funcargs <<< "$func";
                        export FICTION_ROUTE="$REQUEST_PATH";
                        [[ "$func" == 'echo' ]] && $func ${funcargs//\"/\\\"} || $func "${funcargs//\"/\\\"}";
                    else
                        show_404;
                    fi
                else
                    show_404;
                fi
            else
                show_404;
            fi
        fi
    else
        httpSendStatus 404;
        sendError "404 Page Not Found";
    fi
}

function parseAndPrint() {
  time1=$(date +%s%3N)
  verbose=true
  local REQUEST_METHOD REQUEST_PATH HTTP_VERSION QUERY_STRING
  local -A HTTP_HEADERS
  declare -Ag POST 
  declare -Ag GET
  local -A HTTP_RESPONSE_HEADERS
  local -A COOKIE
  local -A SESSIONS
  local -a cookie_to_send
  
  read -r REQUEST_METHOD REQUEST_PATH HTTP_VERSION
  HTTP_VERSION="${HTTP_VERSION%%$'\r'}"
  [[ "$HTTP_VERSION" =~ HTTP/[0-9]\.?[0-9]? ]] && HTTP_VERSION="${BASH_REMATCH[0]}"
  [[ -z "$REQUEST_METHOD" || -z "$REQUEST_PATH" ]] && return

  local line _h
  while read -r line; do
    line="${line%%$'\r'}"
    [[ -z "$line" ]] && break
    _h="${line%%:*}"
    HTTP_HEADERS["${_h,,}"]="${line#*: }"
  done
  unset line _h

  local entry
  IFS='?' read -r REQUEST_PATH get <<<"$REQUEST_PATH"
  get="$(urldecode "$get")"
  IFS='#' read -r REQUEST_PATH _ <<<"$REQUEST_PATH"
  QUERY_STRING="$get"
  IFS='&' read -ra data <<<"$get"
  for entry in "${data[@]}"; do
    GET["${entry%%=*}"]="${entry#*=}"
  done
  REQUEST_PATH="$(dirname "$REQUEST_PATH")/$(basename "$REQUEST_PATH")"
  REQUEST_PATH="${REQUEST_PATH#/}"

  entry=''

  local -a cookie
  local key value
  IFS=';' read -ra cookie <<<"${HTTP_HEADERS["cookie"]}"
  [ -n "${HTTP_HEADERS["Cookie"]}" ] && ((${#cookie[@]} < 1 )) && cookie+=( ${HTTP_HEADERS["cookie"]//;} )
  for entry in ${cookie[@]}; do
    IFS='=' read -r key value <<<"$entry"
    [[ "$key" ]] && COOKIE["$key"]="${value}"
  done
  unset entry cookie key value

  if [[ "$REQUEST_METHOD" == "POST" ]] && ((${HTTP_HEADERS['content-length']:=0} > 0)); then
    local entry
    if [[ "${HTTP_HEADERS["content-type"]}" == "application/x-www-form-urlencoded" ]]; then
      IFS='&' read -rN "${HTTP_HEADERS["Content-Length"]}" -a data
      for entry in "${data[@]}"; do
        entry="${entry%%$'\r'}"
        POST["${entry%%=*}"]="${entry#*:}"
      done
    elif [[ "${HTTP_HEADERS["content-type"]}" == "application/json" ]]; then 
      read -N "${HTTP_HEADERS["content-length"]}" data
      eval $(json_to_arr "${data%%$'\r'}" POST) 
    else
      read -rN "${HTTP_HEADERS["content-length"]}" data
      POST["raw"]="${data%%$'\r'}"
    fi
    unset entry
  fi
  
  buildResponse
  unset POST GET
  "${verbose:=false}" && echo "[$(date)] $REQUEST_METHOD $REQUEST_PATH $status $(($(date +%s%3N)-time1))ms" >&2
  unset HTTP_VERSION REQUEST_METHOD REQUEST_PATH status
}

# HelperFns
function FictionServePath() {
  # FictionServePath <from> <to:fn> <as> <type?>
  [[ -z "$1" || -z "$2" ]] && return 1
  mktmpDir
  local type="${4:-static}"
  if [[ "$FICTION_BUILD" ]]; then 
    [[ "$3" == text/html ]] || return
  fi

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

show_404() {
  INCLUDE_DOM=false
  INCLUDE_LUCIDE=false
  httpSendStatus 404
  sendError "404 Page Not Found"
  return
}


function FictionServeDynamicPath() {
  # FictionServeDynamicPath <from> <to:fn> <as>
  [[ -z "$1" || -z "$2" ]] && return 1
  FictionServePath "$1" "$2" "$3" dynamic
}

function FictionServeCGI() {
  FictionServePath "${2:-/${1//.\/}}" "$1" "$3" cgi
}

function FictionServeFile() { 
    [ ! -f "$1" ] && error "$1 is not a file" && return 1
    local ROUTEFN="FR$(uuidgen)";
    eval "${ROUTEFN}(){ cat \"$1\"; }";
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
    FictionServePath "${ROUTEPATH}" "${ROUTEFN}" "${3:-$(file --mime-type -b "${1}")}"
}

function FictionServeDir() { 
    local ROUTE_APPEND="$2";
    local download="$3";
    [[ "${download:-true}" == true ]] && local type=application/x-octet-stream;
    if [[ -n "$ROUTE_APPEND" ]] && [[ "${ROUTE_APPEND: -1}" == "/" ]]; then
        ROUTE_APPEND="${ROUTE_APPEND:0:0-1}";
    fi
    if [ -d "$1" ]; then
        [[ "${4:-true}" == true ]] && FictionServePath "${ROUTE_APPEND}" "tree -H '$ROUTE_APPEND' -L 1 '$1'" "text/html";
        test -e "$1/"* > /dev/null 2>&1 && for item in ${1}/*;
        do
            if [ -d "$item" ]; then
                [[ "${5:-true}" == true ]] && FictionServeDir "${item}" "${ROUTE_APPEND}/${item##*/}" > /dev/null;
            else
                ROUTEPATH="${item}";
                if [ "${ROUTEPATH::1}" == "." ]; then
                    ROUTEPATH="${ROUTEPATH:1}";
                fi;
                FictionServeFile "${item}" "${ROUTE_APPEND}/${ROUTEPATH##*/}" "$type" > /dev/null;
            fi;
        done;
    else
        error "$1 is not a directory"
        return 1;
    fi
}



function FictionHttpServer () { 
    [[ "$FICTION_BUILD" ]] && return
    local origaddress="$1";
    if [[ "$origaddress" =~ "https://" ]]; then
        HTTPS=true;
        origaddress="${origaddress//https:\/\//}";
    else
        if [[ "$origaddress" =~ "http://" ]]; then
            origaddress="${origaddress//http:\/\//}";
        fi
    fi
    IFS=':' read -r address port <<< "$origaddress";
    [ -z "$port" ] && { 
        "${HTTPS:=false}" && port=443 || port=80
    };
    BIND_ADDRESS="$address";
    HTTP_PORT="$port";
    shift;
    if [[ "$#" > 0 ]]; then
        for arg in "${@}";
        do
            IFS='=' read key value <<< "$arg";
            [[ -z "$value" ]] && continue;
            case "$key" in 
                ssl)
                    HTTPS=true
                ;;
                ssl_cert)
                    [ -f "$value" ] && SSL_CERT="$value" || { 
                        error "ssl_cert: $value: no such file" && return 1
                    }
                ;;
                ssl_key)
                    [ -f "$value" ] && SSL_KEY="$value" || { 
                        error "ssl_key: $value: no such file" && return 1
                    }
                ;;
                core)
                    core="$value"
                ;;
                *)
                    error "Illegal option: $key" 1>&2;
                    return 1
                ;;
            esac
        done
    fi
    echo -e "\nStarting Fiction (${_green}$FICTION_VERSION${_nc})"
    mktmpDir
    case "$core" in 
        bash)
            if "${HTTPS:=false}"; then
                echo "HTTPS is not supported in bash mode" 1>&2;
                exit 1;
            else
                [ ! -f "$FICTION_PATH/accept" ] && error "\`accept\` is not found in $FICTION_PATH" && return 1;
                enable -f "$FICTION_PATH/modules/accept" accept;
                [[ "$port" = 80 ]] && echo -e "\nServer address: http://$address (single connection mode)" || echo -e "\nServer address: http://$address:$port (single connection mode)";
                #echo "$(tput setaf 3)Warning:${_nc} In current mode the server manages only one connection at the time"
                while true; do
                    accept -b "$BIND_ADDRESS" -r REMOTE_ADDR "${HTTP_PORT}";
                    if [[ $? = 0 && -n "$ACCEPT_FD" ]]; then
                        parseAndPrint <&${ACCEPT_FD} >&${ACCEPT_FD};
                        exec {ACCEPT_FD}>&-;
                    else
                        return 1;
                    fi
                done
            fi
        ;;
        nc | netcat | ncat | socat)
            echo "FICTION_PATH='$FICTION_PATH'" >> "$serverTmpDir/worker.sh";
            declare | \
            grep -vE '(SSH_|^PWD|^OLDPWD|^TERM|^HOME|^USER|^PATH|^BASH_*|^BASHOPTS|^EUID|^PPID|^SHELLOPTS|^UID)' >>"$serverTmpDir/worker.sh"
            chmod +x "$serverTmpDir/worker.sh";
            cat >> "$serverTmpDir/job.sh" <<EOF
#!/bin/bash
HEADERS=""
while read -r val; do
  val="\${val//$'\r'/}"
  HEADERS+="\$val"$'\n'
  [[ "\${val,,}" =~ 'content-length' ]] && IFS=':' read key value <<< "\${val,,}"
  [[ "\${#val}" < 1 ]] && break
done
[[ "\${value// }" -gt 1 ]] && { read -rn \${value// } -t1 data; [[ \${#data} > 1 ]] && HEADERS+="\${data//$'\r'/}"$'\n'; unset key value data; }
[[ "\$NCAT_REMOTE_ADDR" ]] && REMOTE_ADDR="\$NCAT_REMOTE_ADDR" || REMOTE_ADDR="\$FICTION_PEERADDR"
. $workerargs $serverTmpDir/worker.sh
parseAndPrint <<<"\$HEADERS"
EOF

            chmod +x "$serverTmpDir/job.sh";
            trap clean EXIT;
            echo -n "Server address: ";
            case "${core:-socat}" in 
                socat)
                    which socat >/dev/null || { error "cannot find socat binary" && return 1; }
                    if "${HTTPS:=false}"; then
                        [[ "$port" = 443 ]] && echo -n "https://$address" || echo -n "https://$address:$port";
                        echo " (forking mode)";
                        exec -a "fiction" socat openssl-listen:"$HTTP_PORT",bind="$BIND_ADDRESS",verify=0,cert="$SSL_CERT",key="$SSL_KEY",reuseaddr,fork SYSTEM:"$serverTmpDir/job.sh";
                    else
                        [[ "$port" = 80 ]] && echo -n "http://$address" || echo -n "http://$address:$port";
                        echo " (forking mode)";
                        exec -a "fiction" socat TCP-LISTEN:$HTTP_PORT,bind="$BIND_ADDRESS",reuseaddr,fork EXEC:''"$serverTmpDir"'/job.sh';
                    fi
                ;;
                ncat)
                    which ncat >/dev/null || { error "cannot find ncat binary" && return 1; }
                    if "${HTTPS:=false}"; then
                        [[ "$port" = 443 ]] && echo -n "https://$address" || echo -n "https://$address:$port";
                        echo " (forking mode)";
                        exec -a "fiction" ncat -klp "$HTTP_PORT" -c "$serverTmpDir/job.sh" --ssl --ssl-cert "$SSL_CERT" --ssl-key "$SSL_KEY";
                    else
                        [[ "$port" = 80 ]] && echo -n "http://$address" || echo -n "http://$address:$port";
                        echo " (forking mode)";
                        exec -a "fiction" ncat -klp "$HTTP_PORT" -c "$serverTmpDir/job.sh";
                    fi
                ;;
                nc | netcat)
                    which nc >/dev/null || { error "cannot find netcat binary" && return 1; }
                    if "${HTTPS:=false}"; then
                        error "HTTPS is not supported in legacy netcat mode" 1>&2
                    else
                        [[ "$port" = 80 ]] && echo -n "http://$address" || echo -n "http://$address:$port";
                        echo " (forking mode)";
                        nc --version 2> 1 > /dev/null && nc_path="nc.traditional" || nc_path="nc";
                        while true; do
                            exec -a "fiction" $nc_path -vklp "$HTTP_PORT" -e "$serverTmpDir/job.sh";
                            echo $?;
                        done
                    fi
                ;;
            esac
        ;;
    esac
}


if ! (return 0 2>/dev/null); then
  case "$1" in 
    run)
      if ! declare -F bashx >/dev/null 2>&1; then
        if [ -f "$bashx_path" ]; then 
          BASHX_NESTED=true
          source "$bashx_path"
        else 
          error "cannot load bashx ($bashx_path)" >&2
          exit 1
        fi
      fi
      [[ "$2" ]] && default_index="$2"
      BASHX_VERBOSE=true
      bashx "$default_index"
    ;;
    build)
      echo "Initializing build..."
      time=$(date +%s%3N)
      if ! declare -F bashx >/dev/null 2>&1; then
        if [ -f "$bashx_path" ]; then 
          BASHX_NESTED=true
          source "$bashx_path"
        else 
          error "cannot load bashx ($bashx_path)"
          exit 1
        fi
      fi
      FICTION_BUILD=true
      [[ "$2" ]] && default_index="$2"
      [[ "$3" ]] && target_dir="$3"
      BASHX_VERBOSE=true
      bashx "$default_index"
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
Fiction $FICTION_VERSION
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
  if [[ "${BASH_SOURCE[-1]}" =~ .shx|.bashx ]]; then
    if ! declare -F bashx >/dev/null 2>&1; then
        if [ -f "$bashx_path" ]; then 
          BASHX_NESTED=true
          bash "$bashx_path" "${BASH_SOURCE[-1]}"
          exit
        else 
          error "cannot load bashx ($bashx_path)"
          exit 1
        fi
    fi 
  fi
fi