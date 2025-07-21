#!/bin/bash
# The Fiction(R) Library!
# Configurations
FICTION_HTML_ELEMENTS="h1 h2 h3 h4 h5 h6 p a img ul ol li div span table td th thead tbody tfoot form input textarea button option label br hr em strong i b u s sub sup code pre blockquote article section nav header footer aside main details summary dialog figure figcaption audio video track canvas svg iframe object embed param meta link script style title base body html doctype noscript template slot picture srcset map area tracktime datalist fieldset legend output progress meter menu mark rt rp wbr bdi bdo abbr address cite dfn ins del kbd samp var" # thanks gemini

# Http Server
FICTION_HTTP_ERROR_BEGIN="<html style='font-family:sans-serif;'><title>Error</title><center>"
FICTION_HTTP_ERROR_END="<hr><p>Fiction Web Server</h1></center></html>"
workerargs=""
# Helper functions
function fiction_sanitize_html() {
  # https://stackoverflow.com/a/12873723
  [[ ! "$@" =~ '%'|'<'|'>'|\"|\' ]] && printf "%s" "$@" && return
  printf "%s" "$@" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'"'"'/\&#39;/g'
  #local string="${@//\%/&amp;}"
  #string="${string//</&lt;}"
  #string="${string//>/&gt;}"
  #string="${string//\"/&quot;}"
  #string="${string//\'/&#39;}"
  # printf "$string"
}

# Handler

function fiction_element() {
  echo -n "<${1}"
  shift
  for arg in "$@"; do
    echo -n " " # very necessary
    if [[ "$arg" == *"="* ]]; then
      # Do sanitization
      IFS='=' read -r key value <<<"$arg"
      if [[ "${key,,}" =~ onclick ]]; then 
        IFS=' ' read -r cmd _ <<< "$value"
        if type "$cmd" &>/dev/null; then
          local name="$(addServerAction "$value")"
          value="fetch('$name',{method:'POST',headers:{'X-CSRF-Token':document.querySelector('meta[name=csrf-token]').content}})"
        fi
      fi
      fiction_sanitize_html "$key=" # by html standards, key musn't have quotes

      echo -n '"'
      fiction_sanitize_html "$value"
      echo -n '"' # Add quotes bc why not
    else
      fiction_sanitize_html "$arg"
    fi
  done
  echo -ne ">"
}

function fiction_closing_element() {
  echo -ne "</${1}>"
}

function str() {
  fiction_sanitize_html "$@"
}

function @parse {
  for arg in $@; do 
    IFS='=' read key value <<< "${arg##;}"; 
    [ -z "$key" ] && continue
    printf -v $key "%s" "$value"
  done
}

function @wrapper() {
  [ -z "$(declare -F "$1")" ] && return
  eval "$(declare -f "$1" | sed "s+{@children};+}; /${1}(){+g")"
}

function @cache() {
  [ -z "$(declare -F "$1")" ] && return
  while declare -f "$1" | grep -q "{cache}"; do

    local CACHEBLOCK_BEGIN=0
    local CACHEBLOCK_END=0
    local linenum=1
    while IFS= read -r line; do
      if [[ "$line" == *"{cache};"* ]]; then
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
  [ -z "$(declare -F "$1")" ] && return
  @cache "$1" # just in case
  local PRERENDER_DATA="$1(){ echo \"$(eval "$1" | sed 's+"+\\"+g')\"; }"
  eval "$PRERENDER_DATA"
  if [ -n "$(declare -F "\\$1")" ]; then
    PRERENDER_DATA="\\$1(){ echo \"$(eval "\\$1" | sed -e 's+"+\\"+g')\"; }"
    eval "$PRERENDER_DATA"
  fi
}

function addServerAction() {
  [ -z "$1" ] && return 
  local path="/__server-action_$(openssl rand -hex 10)"
  FictionServePath "$path" "$1" "" >/dev/null
  [[ $? == 0 ]] && echo "$path" || return 
  unset path
}

function import() {
  # Syntax: import <filename>  || import <filename> as <ElementAlias>
  # import <function> from <filename> || import <function> from <filename> as <ElementAlias>
  local name filename
  [ -z "$name" ] && name="$1"
  shift
  if [[ "$1" == "as" ]]; then
    if [ ! -f "$name" ]; then
      echo "$name not found to import."
      exit 1
    fi
    shift
    if [ -z "$1" ]; then
      fn_name=""${name%.*}""
    else
      fn_name="$1"
    fi
    eval "${fn_name}() { source \"$name\"; }"
  elif [[ "$1" == "from" ]]; then
    shift
    filename="$1"
    if [ ! -f "$filename" ]; then
      echo "$name not found to import."
      exit 1
    fi
    local funcout="$(sed -n '/'"$name"'.*\(\)/,/^}/p' "$filename")"
    shift
    if [[ "$1" == "as" ]]; then
      shift
      if [ -z "$1" ]; then
        fn_name="${name%.*}"
      else
        fn_name="$1"
      fi
      eval "${funcout/$name/$fn_name}"
    else
      [[ -n "$funcout" ]] && eval "$funcout"
    fi
  fi
}

function @jsFunction {
  local invoke="$2"
  [ -z "$(declare -F "$1")" ] && return
  funccontents=$(declare -f "$1")
  "${invoke:=false}" && funccontents=$(echo "${funccontents}" | sed -e "s+{+{\n printf '(() => {'+" -e "s+\(.*\)}+\1  printf '})()'; }+" ) || \
                        funccontents=$(echo "${funccontents}"  | sed -e "s+{+{\n printf '() => {'+" -e "s+\(.*\)}+\1  printf '}' };+" )
  eval "$funccontents"
}


# -- Init
# Generate HTML Element fn wrappers
for elem in $FICTION_HTML_ELEMENTS; do
  eval "${elem}() { fiction_element ${elem} \"\$@\"; }; /${elem}() { fiction_closing_element ${elem} \"\$@\"; }"
done

function reloadPage() {
  printf "window.location.reload();"
}

function alert() {
  printf "%s" "alert('$@'); "
}

function editElement() {
  local id="$1"
  local attributes="$2"
  local content="$3"
  local delay="$4"
  [ -n "$delay" ] && printf "setTimeout(() => { "
 #() => { 
  printf "%s" "const el = document.getElementById('$id');if (!el) return; $([ -n "${attributes}" ] && echo "'$attributes'.split(' ').forEach(pair => { const [key, val] = pair.split('='); if (key && val) el.setAttribute(key, val);});") el.innerHTML = '${content}'; "

 [ ! -z "$delay" ] && printf "}, '%s');" "$delay"
}

function testButton() {
  local name=${RANDOM}
  #FictionServePath "/__server-action$name" "" "text/plain" >&2
  #(button onclick="fetch('/__server-action$name',{method:'POST',headers:{'X-CSRF-Token':document.querySelector('meta[name=csrf-token]').content}})")
  (button onclick="$1")
  str "Toggle Div"
(/button)
}

# ---- END OF HTML LIBRARY ----
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

send_encoded_frame() {
  local first_byte="0x81"
  local hex_string binary

  # TODO: Get this working!
  #    printf -v 'hex_string' '%s0x%x' "$first_byte" "${#1}"
  #    for ((i = 0; i < ${#hex_string}; i += 2)); do
  #        binary+="\x${hex_string:i:2}"
  #    done
  #    _verbose 4 "$binary"

  printf '%s0x%x' $first_byte "${#1}" | xxd -r -p
  printf '%s' "$1"
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
  statuscode="$1"
  httpSendStatus "$statuscode"
  local filename=''
  [[ $1 == 401 ]] &&
    {
      HTTP_RESPONSE_HEADERS['WWW-Authenticate']="Basic realm=WebServer"
      printf '%s %s\n' "HTTP/1.1" "${HTTP_RESPONSE_HEADERS["status"]:=$statuscode}"
      unset 'HTTP_RESPONSE_HEADERS["status"]'

      for value in "${cookie_to_send[@]}"; do
        printf 'Set-Cookie: %s\n' "$value"
      done
      for key in "${!HTTP_RESPONSE_HEADERS[@]}"; do
        printf '%s: %s\n' "${key,,}" "${HTTP_RESPONSE_HEADERS[$key]}"
      done
      return
    }
  filename="$serverTmpDir/output_$RANDOM"
  [ -f "$filename" ] && rm "$filename"
  "$run" >"$filename"
  if [[ -z "${FictionRouteContentType["${REQUEST_PATH}"]}" || "${FictionRouteContentType["${REQUEST_PATH}"]}" == "auto" ]]; then
    local _ char type="$(file --mime "$filename")"
    IFS=' ' read _ type char <<<"$type"
    which file 2>&1 >/dev/null && HTTP_RESPONSE_HEADERS["content-type"]="${type//;/}"
    unset _ type char
  else
    HTTP_RESPONSE_HEADERS["content-type"]="${FictionRouteContentType["${REQUEST_PATH}"]:-html}"
  fi

  printf '%s %s\n' "HTTP/1.1" "${HTTP_RESPONSE_HEADERS["status"]}"
#  unset 'HTTP_RESPONSE_HEADERS["status"]'

  for value in "${cookie_to_send[@]}"; do
    printf 'Set-Cookie: %s\n' "$value"
  done
  # printf '%s\n' "$(<"$filename")"
  if [[ "${HTTP_RESPONSE_HEADERS["content-type"]}" =~ html ]]; then 
    local isdoctype=false ishtml=false isbody=false iscbody=false ishead=false ischtml=false ischead=false
    local output=$(cat "$filename")
    [[ "$output" =~ '<!DOCTYPE html>' ]] && isdoctype=true
    [[ "$output" =~ \<html ]] && { ishtml=true; [[ "$output" =~ '</html>' ]] && ischtml=true; }
    [[ "$output" =~ \<body ]] && { isbody=true; [[ "$output" =~ '</body>' ]] && iscbody=true; }
    [[ "$output" =~ '<head>' ]] && { ishead=true; [[ "$output" =~ '</head>' ]] && ischead=true; }
    ! "$isdoctype" &&  sed -i "1s|^|<!DOCTYPE html>|" "$filename"
    ! "$ishtml" && sed -i "1s|<!DOCTYPE html>|<!DOCTYPE html><html>|" "$filename"
    local csrf=$(sessionGet "$SESSION_ID")
    [[ -n "$csrf" && ! "$statuscode" =~ 401|404 ]] && {
      "$ishead" && sed -i "s|<head>|<head><meta name='csrf-token' content='$csrf'>|" "$filename" || sed -i "s|<html>|<html><head><meta name='csrf-token' content='$csrf'></head>|" "$filename";
      ! "$ischead" && "$isbody" && sed -i "s|</head>" "$filename";
    }
    ! "$isbody" && "$ischead" && sed -i "s|</head>|<body>" "$filename"
    ! "$iscbody" && printf "</body>" >>"$filename"
    ! "$ischtml" && printf "</html>" >>"$filename"
    read size filename < <(wc -c "$filename")
    HTTP_RESPONSE_HEADERS["content-length"]="${size:=0}"
    for key in "${!HTTP_RESPONSE_HEADERS[@]}"; do
      printf '%s: %s\n' "${key,,}" "${HTTP_RESPONSE_HEADERS[$key]}"
    done
    printf "\n"
    cat "$filename"
  else 
    read size filename < <(wc -c "$filename")
    HTTP_RESPONSE_HEADERS["content-length"]="${size:=0}"
    for key in "${!HTTP_RESPONSE_HEADERS[@]}"; do
      printf '%s: %s\n' "${key,,}" "${HTTP_RESPONSE_HEADERS[$key]}"
    done
    printf "\n"
    cat "$filename"
  fi
  printf "\n"
  rm "$filename"
}
__x4gT9q6=( "$(openssl rand -hex 32)" "$(openssl rand -hex 16)" );
parseAndPrint() {
  verbose=true
  local REQUEST_METHOD REQUEST_PATH HTTP_VERSION QUERY_STRING
  local -A HTTP_HEADERS
  local -A POST
  local -A GET
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
    GET["${entry%%=*}"]="${entry#*:}"
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
  if [[ -z "${COOKIE['session_id']}" ]]; then
    sessionSet
  else 
    SESSION_ID="${COOKIE['session_id']}"
  fi
  # Parse post data only if length is > 0 and post is specified
  # bash (( will not fail if var is not a number, it will just return 1, no need of int check
  if [[ "$REQUEST_METHOD" == "POST" ]] && ((${HTTP_HEADERS['content-length']:=0} > 0)); then
    local entry
    if [[ "${HTTP_HEADERS["content-type"]}" == "application/x-www-form-urlencoded" ]]; then
      IFS='&' read -rN "${HTTP_HEADERS["Content-Length"]}" -a data
      for entry in "${data[@]}"; do
        entry="${entry%%$'\r'}"
        POST["${entry%%=*}"]="${entry#*:}"
      done
    else
      read -rN "${HTTP_HEADERS["content-length"]}" data
      POST["raw"]="${data%%$'\r'}"
    fi
    unset entry
  fi

  buildResponse 200
  "${verbose:=false}" && echo "[$(date)] $HTTP_VERSION $REQUEST_METHOD $REQUEST_PATH ${HTTP_RESPONSE_HEADERS['status']}" >&2
}

basicAuth() {
  local authData
  local user password

  [[ -f "$BASIC_AUTH_FILE" ]] || {
    echo "Missing \$BASIC_AUTH_FILE" >&2
    return 1
  }

  if [[ -z "${HTTP_HEADERS["Authorization"]}" ]]; then
    buildResponse 401
    return 0
  fi

  authData="$(base64 -d <<<"${HTTP_HEADERS["Authorization"]# Basic }")"
  IFS=: read -r user password <<<"$authData"

  while read -r r_user r_password; do
    [[ "$r_user" == "$user" && "$r_password" == "$password" ]] && {
      return
    }
  done <"$BASIC_AUTH_FILE"

  buildResponse 401
  return 1
}

__e() {
  openssl enc -aes-256-cbc -K "${__x4gT9q6[0]}" -iv "${__x4gT9q6[1]}" -out "$2" <<< "$1" 
}

__d() {
    openssl enc -d -aes-256-cbc -K "${__x4gT9q6[0]}" -iv "${__x4gT9q6[1]}" -in "$1"
}


sessionGet() {
  [ ! -f "$serverTmpDir/.sessions" ] && { echo ""; return; }
  local s c s1 c1 m=false
  s1=$(echo "$1" | sha256sum)
  ou=$(__d "$serverTmpDir/.sessions" | grep "${s1::-3}")
  [ -n "$ou" ] && IFS=' ' read s c <<< "$ou" || { echo ""; return; }
  [[ "${s1::-3}" == "$s" ]] || { echo ""; return; }
  c1=$(base64 -d <<< "$c")
  echo "$c1"
}

cookieSet() {
  cookie_to_send+=("$1")
}

sessionSet() {
  if [ ! -f "$serverTmpDir/.sessions" ]; then
    : >"$serverTmpDir/.sessions"
    local session="$(generate_session_id)" 
    local ssession=$(echo "$session" | sha256sum)
    local tok="$(generate_csrf_token | base64)"
    __e "${ssession::-3} $tok" "$serverTmpDir/.sessions"
    cookieSet "session_id=${session}; HttpOnly; max-age=5000"
    unset session tok
  else 
    local ou="$(__d "$serverTmpDir/.sessions")"
    local session="$(generate_session_id)" 
    local ssession=$(echo "$session" | sha256sum)
    local tok="$(generate_csrf_token | base64)"
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

serveHtml() {
  # Don't allow going out of DOCUMENT_ROOT
  case "$REQUEST_PATH" in
  *".."* | *"~"*)
    httpSendStatus 404
    sendError "404 Page Not Found"
    return
    ;;
  esac
  REQUEST_PATH="$(dirname "$REQUEST_PATH")/$(basename "$REQUEST_PATH")"
  REQUEST_PATH="${REQUEST_PATH#/}"
  [ "${REQUEST_PATH::2}" == "//" ] && REQUEST_PATH="${REQUEST_PATH:1}"
  if [[ -n "${FictionRoute["$REQUEST_PATH"]}" ]]; then
    printf '%s\n' "$(${FictionRoute["${REQUEST_PATH}"]})"
  else
    httpSendStatus 404
    sendError "404 Page Not Found"
  fi
}

clean() {
  echo "Stopping the server..."
  kill -- -$_pgid || kill $_pid
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
  [ -z "$1" ] && return
  eval "echo \$FICTION_SLUG_$1"
}

# HelperFns
function FictionServePath() {
  # FictionServePath <from> <to:fn> <as>
  echo "Added route: from '$1' to '$2' $([ -n "$3" ] && echo "as '$3'")"
  FictionRoute["$1"]="$2"
  if [ ! -f "$serverTmpDir/.routes" ]; then
    : >"$serverTmpDir/.routes"
    local route="$(sha256sum <<< "$1")"
    local funcname="$(base64 <<< "$2")"
    __e "${route::-3} $funcname" "$serverTmpDir/.routes"
    unset ou route funcname
  else 
    local ou="$(__d "$serverTmpDir/.routes")"
    local route="$(sha256sum <<< "$1")"
    local funcname="$(base64 <<< "$2")"
    ou+=$'\n'"${route::-3} $funcname" 
    __e "$ou" "$serverTmpDir/.routes"
    unset ou route funcname
  fi
  FictionRouteContentType["$1"]="$3"
}

function FictionServeDynamicPath() {
  # FictionServeDynamicPath <from> <to:fn> <as>
  echo "Added dynamic route: from '$1' to '$2' $([ -n "$3" ] && echo "as '$3'")"
  FictionDynamicRoute+=("$1:$2")
  FictionRouteContentType["$1"]="$3"
}

function FictionServeFile() {
  # FictionServeFile <filepath> <alt_path>

  local ROUTEFN="FR$(uuidgen)"
  eval "${ROUTEFN}(){ cat \"$1\"; }"
  local ROUTEPATH
  if [[ -n "$2" ]]; then # if another file path is supplied
    ROUTEPATH="$2"
  else
    ROUTEPATH="${1}"
    if [ "${ROUTEPATH::1}" == "." ]; then
      ROUTEPATH="${ROUTEPATH:1}" # remove .
    fi
    if [[ "${ROUTEPATH::1}" != '/' ]]; then
      ROUTEPATH="/${ROUTEPATH}"
    fi
  fi

  FictionServePath "${ROUTEPATH}" "${ROUTEFN}" "$(file --mime-type -b "${1}")"
}

function FictionServeDir() {
  # FictionServeDir "<Dir>" "<atRoute (Optional)>"
  local ROUTE_APPEND="$2"
  if [[ -n "$ROUTE_APPEND" ]] && [[ "${ROUTE_APPEND: -1}" == "/" ]]; then
    ROUTE_APPEND="${ROUTE_APPEND:0:0-1}"
  fi

  for item in ${1}/*; do
    if [ -d "$item" ]; then
      FictionServeDir "${item}" "${ROUTE_APPEND}"
    else
      ROUTEPATH="${item}"
      if [ "${ROUTEPATH::1}" == "." ]; then
        ROUTEPATH="${ROUTEPATH:1}" # remove .
      fi
      FictionServeFile "${item}" "${ROUTE_APPEND}${ROUTEPATH}"
    fi
  done
}

# Init HttpLib

function generate_csrf_token() {
  openssl rand -base64 48
}

function generate_session_id() {
  openssl rand -hex 48
}

function FictionRequestHandler() {
  # Don't allow going out of DOCUMENT_ROOT
  case "$REQUEST_PATH" in
  *".."* | *"~"*)
    httpSendStatus 404
    sendError "404 Page Not Found"
    return
    ;;
  esac

  [ "${REQUEST_PATH::2}" == "//" ] && REQUEST_PATH="${REQUEST_PATH:1}"
  [ "${REQUEST_PATH::1}" != "/" ] && REQUEST_PATH="/${REQUEST_PATH}" # BUG wtf
  if [[ -n "${FictionRoute["$REQUEST_PATH"]}" ]]; then
    IFS=' ' read func funcargs <<<"${FictionRoute["${REQUEST_PATH}"]}"
    $func "$funcargs"

  elif [[ ${#FictionDynamicRoute[@]} > 0 ]]; then
    local matching_slugs=0
    IFS='/' read -ra path_keys <<<"${REQUEST_PATH#\/}"
    i=0
    for route in ${FictionDynamicRoute[@]}; do
      IFS=':' read route funcname <<<"$route"
      IFS=' ' read func funcargs <<<"$funcname"
      IFS='/' read -ra route_keys <<<"${route#\/}"
      for subroute in ${route_keys[@]}; do
        if [[ $subroute =~ '[' ]]; then
          local slug="${subroute#\[}"
          slug="${slug%\]}"
          printf -v "FICTION_SLUG_$slug" "%s" "${path_keys[$i]}"
          ((matching_slugs++))
        elif [[ ! $route =~ ${route_keys[$i]} ]]; then
          break
        fi
        ((i++))
      done
      ((matching_slugs > 0)) && $func "$funcargs"
    done
  elif [ -f "$serverTmpDir/.routes" ]; then
    local csrf=$(sessionGet "${COOKIE['session_id']}")
    if [[ "$REQUEST_PATH" =~ '__server-action' ]] && [[ -z "${HTTP_HEADERS['x-csrf-token']}" || "${HTTP_HEADERS['x-csrf-token']}" != "$csrf" ]]; then
      httpSendStatus 401 
      sendError "401 Prohibited"
      return
    fi
    local r f r1 f1 m=false
    r1=$(echo "$REQUEST_PATH" | sha256sum)
    ou=$(__d "$serverTmpDir/.routes" | grep "${r1::-3}")
    [ -n "$ou" ] && IFS=' ' read r f <<< "$ou" || { httpSendStatus 404; sendError "401 Prohibited"; return; }
    [[ "${r1::-3}" == "$r" ]] || { httpSendStatus 404; sendError "401 Prohibited"; return; }
    f1=$(base64 -d <<< "$f")
    IFS=' ' read func funcargs <<<"$f1"
    $func "$funcargs"
  else
    httpSendStatus 404
    sendError "404 Page Not Found"
  fi
}



if [[ -z "$serverTmpDir" ]]; then
    export serverTmpDir="$(mktemp -d)"
    # export TMPDIR="/tmp"
fi

function FictionHttpServer() {
  # FictionHttpServer <port>
  local origaddress="$1"
  if [[ "$origaddress" =~ "https://" ]]; then
    HTTPS=true
    origaddress="${origaddress//https:\/\//}"
  elif [[ "$origaddress" =~ "http://" ]]; then
    origaddress="${origaddress//http:\/\//}"
  fi
  IFS=':' read -r address port <<<"$origaddress"
  [ -z "$port" ] && { "${HTTPS:=false}" && port=443 || port=80; }
  export BIND_ADDRESS="$address" HTTP_PORT="$port"
  shift
  while [[ "$#" -gt 0 ]]; do
    case "${1}" in
    https)
      shift
      shift
      HTTPS=true
      local cert="$1"
      shift
      shift
      local key="$1"
      shift
      SSL_CERT="$cert"
      SSL_KEY="$key"
      echo "Enabled HTTPS with cert file $cert and key file $key"
      ;;
    dynamic)
      shift
      shift
      local from="$1"
      shift
      shift
      local to="$1"
      shift
      shift
      local as="$1"
      shift
      FictionServeDynamicPath "$from" "$to" "$as"
      ;;
    route)
      shift
      local from="$1"
      shift
      shift
      local to="$1"
      shift
      shift
      local as="$1"
      shift
      FictionServePath "$from" "$to" "$as"
      ;;
    serve)
      shift
      local item="$1"
      local alt_path=""
      shift
      if [[ "$1" == "at" ]]; then
        shift
        alt_path="$1"
        shift
      fi

      if [ -d "$item" ]; then
        echo ">>> Serving directory $item $([ -n "$alt_path" ] && echo "at $alt_path")"
        FictionServeDir "$item" "$alt_path"
        echo ">>> End of directory listing."
      else
        echo ">>> Serving file $item $([ -n "$alt_path" ] && echo "at $alt_path")"
        FictionServeFile "$item" "$alt_path"
      fi
      ;;
    *)
      echo "Unknown argument: $1"
      shift
      ;;
    esac
  done

  # setup
  export run="FictionRequestHandler"
  #local -a tmps=(/tmp/tmp.*)
  #for tmp in ${tmps[@]}; do 
  #  rm -r "$tmp"
  #done
  # create worker
  declare -A >"$serverTmpDir/worker.sh"
  declare -a | grep -vE '(BASH_VERSINFO)'  >>"$serverTmpDir/worker.sh"
  declare | \
  grep -vE '(SSH_|^PWD|^OLDPWD|^TERM|^HOME|^USER|^PATH|BASH_VERSINFO|^BASHOPTS|^EUID|^PPID|^SHELLOPTS|^UID)' | \
  sed \
   -e 's+(head+(fiction_element head+g' \
   -e 's+(/head)+echo "</head>"+g' \
   -e 's+(tr+(fiction_element tr+g' \
   -e 's+(/tr)+echo "</tr>"+g' \
   -e 's+(command+(fiction_element command+g' \
   -e 's+(/command)+echo "</command>"+g' \
   -e 's+(ruby+(fiction_element ruby+g' \
   -e 's+(/ruby)+echo "</ruby>"+g' >>"$serverTmpDir/worker.sh"

  echo "parseAndPrint" >>"$serverTmpDir/worker.sh"
 # echo '[[ -d "$serverTmpDir" ]] && rm -r "$serverTmpDir"' >>"$serverTmpDir/worker.sh"
  chmod +x "$serverTmpDir/worker.sh"
  cat >"$serverTmpDir/job.sh" <<EOF
#!/bin/bash
HEADERS=""
while read -r val; do
  HEADERS+="\${val//$'\r'/}"$'\n'
  if [ "\${#val}" == "1" ]; then
    break
  fi
done
echo "\$HEADERS" | exec -a "fiction-worker" bash $workerargs $serverTmpDir/worker.sh
EOF
  chmod +x "$serverTmpDir/job.sh"
  trap clean EXIT
  if "${HTTPS:=false}"; then 
    [[ "$port" = 443 ]] && echo -e "\nServing your webserver at https://$address" || echo -e "\nServing your webserver at https://$address:$port"
    exec -a "fiction" socat openssl-listen:"$HTTP_PORT",bind="$BIND_ADDRESS",verify=0,cert="$SSL_CERT",key="$SSL_KEY",reuseaddr,fork SYSTEM:"$serverTmpDir/job.sh"
  else 
    trap clean EXIT
    [[ "$port" = 80 ]] && echo -e "\nServing your webserver at http://$address" || echo -e "\nServing your webserver at http://$address:$port"
    exec -a "fiction" socat TCP-LISTEN:$HTTP_PORT,bind="$BIND_ADDRESS",reuseaddr,fork SYSTEM:"$serverTmpDir/job.sh"
  fi
}
