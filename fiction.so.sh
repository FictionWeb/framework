#!/bin/bash
# The Fiction(R) Library!
# Configurations
FICTION_HTML_ELEMENTS="h1 h2 h3 h4 h5 h6 p a img ul ol li div span table tr td th thead tbody tfoot form input textarea button option label br hr em strong i b u s sub sup code pre blockquote article section nav header footer aside main details summary dialog figure figcaption audio video track canvas svg iframe object embed param meta link script style title base head body html doctype noscript template slot picture srcset map area tracktime datalist fieldset legend output progress meter menu command keygen mark ruby rt rp wbr bdi bdo abbr address cite dfn ins del kbd samp var" # thanks gemini

# Http Server
FICTION_HTTP_ERROR_BEGIN="<title>Error!!!</title><center><h1>Fiction Web Server</h1><hr>"
FICTION_HTTP_ERROR_END="</center>"

# Helper functions
function fiction_sanitize_html() {
  # https://stackoverflow.com/a/12873723
  echo -n "$@" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'"'"'/\&#39;/g'
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
      fiction_sanitize_html "$key=" # by html standards, key musn't have quotes

      echo -n "\"$(fiction_sanitize_html "$value")\"" # Add quotes bc why not
    else
      fiction_sanitize_html "$arg"
    fi
  done

  echo -ne ">"
}

function fiction_closing_element() {
  echo -ne "</${1}>"
}

# cmds

function str() {
  fiction_sanitize_html "$@"
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

# -- Init
# Generate HTML Element fn wrappers
for elem in $FICTION_HTML_ELEMENTS; do
  eval "${elem}() { fiction_element ${elem} \"\$@\"; }; /${elem}() { fiction_closing_element ${elem} \"\$@\"; }"
done

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

parseHttpRequest() {
  # Get information about the request
  read -r REQUEST_METHOD REQUEST_PATH HTTP_VERSION
  HTTP_VERSION="${HTTP_VERSION%%$'\r'}"
}

parseHttpHeaders() {
  local line _h _v
  # Split headers and put it inside HTTP_HEADERS, so it can be reused
  while read -r line; do
    line="${line%%$'\r'}"
    [[ -z "$line" ]] && return
    _h="${line%%:*}"
    HTTP_HEADERS["${_h,,}"]="${line#*: }"
  done
}

parseGetData() {
  local entry
  # Split QUERY_STRING into an assoc, so it can be easy reused
  IFS='?' read -r REQUEST_PATH get <<<"$REQUEST_PATH"

  # Url decode get data
  get="$(urldecode "$get")"

  # Split html #
  IFS='#' read -r REQUEST_PATH _ <<<"$REQUEST_PATH"
  QUERY_STRING="$get"
  IFS='&' read -ra data <<<"$get"
  for entry in "${data[@]}"; do
    GET["${entry%%=*}"]="${entry#*:}"
  done
  REQUEST_PATH="$(dirname "$REQUEST_PATH")/$(basename "$REQUEST_PATH")"
  REQUEST_PATH="${REQUEST_PATH#/}"
}

parsePostData() {
  local entry
  # Split POst data into an assoc if is a form, if not create a key raw
  if [[ "${HTTP_HEADERS["Content-type"]}" == "application/x-www-form-urlencoded" ]]; then
    IFS='&' read -rN "${HTTP_HEADERS["Content-Length"]}" -a data
    for entry in "${data[@]}"; do
      entry="${entry%%$'\r'}"
      POST["${entry%%=*}"]="${entry#*:}"
    done
  else
    read -rN "${HTTP_HEADERS["Content-Length"]}" data
    POST["raw"]="${data%%$'\r'}"
  fi
}

parseCookieData() {
  local -a cookie
  local entry key value
  IFS=';' read -ra cookie <<<"${HTTP_HEADERS["Cookie"]}"

  for entry in "${cookie[@]}"; do
    IFS='=' read -r key value <<<"$entry"
    COOKIE["${key# }"]="${value% }"
  done
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

buildHttpHeaders() {
  # We will first send the status header and then all the other headers
 printf '%s %s\n' "HTTP/1.1" "${HTTP_RESPONSE_HEADERS["status"]}"
  unset 'HTTP_RESPONSE_HEADERS["status"]'

  for value in "${cookie_to_send[@]}"; do
    printf 'Set-Cookie: %s\n' "$value"
  done
  for key in "${!HTTP_RESPONSE_HEADERS[@]}"; do
    printf '%s: %s\n' "${key,,}" "${HTTP_RESPONSE_HEADERS[$key]}"
  done
}

websocketStart() {
  websocketStart=1
  websocketRunner="$1"
}

websocketStop() {
  websocketStop=1
}

buildResponse() {
  # Every output will first be saved in a file and then printed to the output
  # Like this we can build a clean output to the client

  local websocketStart websocketRunner websocketStop sha1
  websocketStart=0
  websocketStop=0

  # build a default header
  httpSendStatus "$1"

  [[ $1 == 401 ]] &&
    {
      HTTP_RESPONSE_HEADERS['WWW-Authenticate']="Basic realm=WebServer"
      buildHttpHeaders
      return
    }

  HTTP_RESPONSE_HEADERS["content-type"]=${FictionRouteContentType["${REQUEST_PATH}"]:-html}
  [ -f "$serverTmpDir/output" ] && rm "$serverTmpDir/output"
  "$run" > "$serverTmpDir/output"
  HTTP_RESPONSE_HEADERS["content-length"]="$(wc -c < "$serverTmpDir/output")"
  buildHttpHeaders
  # From HTTP RFC 2616 send newline before body
  printf "\n"
 # printf '%s\n' "$(<"$serverTmpDir/output")"
  cat "$serverTmpDir/output"
  printf "\n"

  # remove tmpfile, this should be trapped...
  # XXX: No needed anymore, since the clean will do the job for use
  # rm "$tmpFile"

  if ((websocketStart)); then
    local websocketStop
    websocketStop=0
    sleep 3
    while true; do
      "$websocketRunner" >"$TMPDIR/output"
      message="$(<"$TMPDIR/output")"
      send_encoded_frame "$message"
      #            encode_message "$message"
      sleep 5
      ((websocketStop)) && break
    done
  fi

}

parseAndPrint() {
  # We will alway reset all variables and build them again
  local REQUEST_METHOD REQUEST_PATH HTTP_VERSION QUERY_STRING
  local -A HTTP_HEADERS
  local -A POST
  local -A GET
  local -A HTTP_RESPONSE_HEADERS
  local -A COOKIE
  local -A SESSION
  local -a cookie_to_send

  # Now mktemp will write create files inside the temporary directory
  local -r TMPDIR="$serverTmpDir"
  # Parse Request
  parseHttpRequest
  [[ -z "$REQUEST_METHOD" || -z "$REQUEST_PATH" ]] && exit 1
  # Create headers assoc
  parseHttpHeaders

  # Basic Auth
  if ((BASIC_AUTH)); then
    basicAuth || return 1
  fi

  # Parse Get Data
  parseGetData

  # Parse cookie data
  parseCookieData

  if [[ -z "${COOKIE["$SESSION_COOKIE"]}" ]] || [[ "${COOKIE["$SESSION_COOKIE"]}" == *..* ]]; then
    SESSION_ID="$(uuidgen)"
  else
    SESSION_ID="${COOKIE["$SESSION_COOKIE"]}"
  fi
  # Parse post data only if length is > 0 and post is specified
  # bash (( will not fail if var is not a number, it will just return 1, no need of int check
  if [[ "$REQUEST_METHOD" == "POST" ]] && ((${HTTP_HEADERS['Content-Length']} > 0)); then
    parsePostData
  fi

  buildResponse 200
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

  # Decode auth data
  # TODO: implement base64 in bash
  authData="$(base64 -d <<<"${HTTP_HEADERS["Authorization"]# Basic }")"

  # Split auth data into user and password
  IFS=: read -r user password <<<"$authData"

  # Check if user and password appear in users.csv
  while read -r r_user r_password; do
    [[ "$r_user" == "$user" && "$r_password" == "$password" ]] && {
      return
    }
  done <"$BASIC_AUTH_FILE"

  buildResponse 401
  return 1
}

sessionStart() {
  [[ -d "${SESSION_PATH}" ]] || {
    echo "Missing Session Path \$SESSION_PATH" >&2
    return 1
  }

  if [[ -f "${SESSION_PATH}/$SESSION_ID" ]]; then
    return 0
  else
    cookieSet "$SESSION_COOKIE=$SESSION_ID; max-age=5000"
    return 1
  fi
}

sessionGet() {
  sessionStart && {
    source "${SESSION_PATH}/$SESSION_ID"
    printf '%s' "${SESSION[$1]}"
  }
}

sessionSet() {
  sessionStart && source "${SESSION_PATH}/$SESSION_ID"
  SESSION["$1"]="$2"
  declare -p SESSION >"${SESSION_PATH}/$SESSION_ID"
}

cookieSet() {
  cookie_to_send+=("$1")
}

sendError() {
  printf '%s\n' "${FICTION_HTTP_ERROR_BEGIN}${@}${FICTION_HTTP_ERROR_END}"
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
  [ -n "$_pid" ] && kill -0 "$_pid" 2>&1 >/dev/null && kill -9 "$_pid"
  [[ -n "$serverTmpDir" && -d "$serverTmpDir" ]] && rm -rf "$serverTmpDir"
}

opensslErrorHandler() {
while read -r line; do
  if [[ "$line" =~ "Address already in use" ]]; then 
    echo "Couldn't bind at port $HTTP_PORT: Address already in use" >&2 
    exit 1
  elif [[ "$line" =~ "Could not open file or uri for loading server certificate private key from route" ]]; then 
    echo "Couldn't load key file $key" >&2 
  fi
done
}

parseandprint() {
  local REQUEST_METHOD REQUEST_PATH HTTP_VERSION QUERY_STRING
  local -A HTTP_HEADERS
  local -A POST
  local -A GET
  local -A HTTP_RESPONSE_HEADERS
  local -A COOKIE
  local -A SESSION
  local -a cookie_to_send
  parseHttpRequest
  parseHttpHeaders
  if ((BASIC_AUTH)); then
    basicAuth || return 1
  fi
  parseGetData
  parseCookieData
  if [[ -z "${COOKIE["$SESSION_COOKIE"]}" ]] || [[ "${COOKIE["$SESSION_COOKIE"]}" == *..* ]]; then
    SESSION_ID="$(uuidgen)"
  else
    SESSION_ID="${COOKIE["$SESSION_COOKIE"]}"
  fi
  if [[ "$REQUEST_METHOD" == "POST" ]] && ((${HTTP_HEADERS['Content-Length']} > 0)); then
    parsePostData
  fi
  buildResponse 200
}

parseAndPrintSSL() {
  kill -0 "$_pid" 2>/dev/null && kill -9 "$_pid"
 # kill -0 "$https_proc_PID" 2>/dev/null && kill -9 "$https_proc_PID"
  coproc https_proc { exec -a "fiction" ncat --ssl -k -l -p "$HTTP_PORT" --ssl-cert "$SSL_CERT" --ssl-key "$SSL_KEY"; } || break
  _pid="$https_proc_PID"
  local i=1;
  #opensslErrorHandler <&3 &
  local headers=""
  while read -u ${https_proc[0]} data; do
    headers+="$data"
    if [[ "${#data}" == "1" ]]; then
      parseAndPrint <<<"$headers" >&${https_proc[1]}
      headers=""
      rm -rf "$serverTmpDir"
      serverTmpDir="$(mktemp -d)"
    fi
  done
  kill -9 "$_pid"
  rm /tmp/fifo
 # kill -9 "$https_proc_PID" 
  set +x
}

parseandprintssl() {
    coproc SSLOUT { openssl s_server -accept 8443 -cert cert.pem -key key.pem -quiet; }
  http_data=""
  serverTmpDir="$(mktemp -d)"
  local headers=""
  while read data <&${SSLOUT[0]}; do
    echo "$data"
    echo WRITE
    headers+="$data"
    echo PASS
    if [ "${#data}" == "1" ]; then
      echo "${headers}"
      echo DATA OK.
      sleep 1
      parseAndPrint <<<"$headers" >&"${SSLOUT[1]}"

      headers=""
      rm -rf "$serverTmpDir"
      serverTmpDir="$(mktemp -d)"
    fi
  done
  exit
}

main() {
  : "${HTTPS:=false}"
  : "${SSL_KEY:=key.pem}"
  : "${SSL_CERT:=cert.pem}"
  : "${HTTP_PORT:=8080}"
  : "${BIND_ADDRESS:=127.0.0.1}"
  : "${TMPDIR:=/tmp}"
  : "${LOGFORMAT:="[%t] - %a %m %U %s %b %T"}"
  : "${LOGFILE:=access.log}"
  : "${LOGGING:=1}"
  : "${SESSION_COOKIE:=BASHSESSID}"
  : "${BASIC_AUTH:=0}"
  TMPDIR="${TMPDIR%/}"

  ! [[ ${BIND_ADDRESS} == "0.0.0.0" ]] && acceptArg="-b ${BIND_ADDRESS}"

  enable -f accept accept || {
    printf '%s\n' "Cannot load accept..."
    exit 1
  }
  enable -f "mktemp" mktemp &>/dev/null || true
  enable -f "rm" rm &>/dev/null || true
  enable -f "finfo" finfo &>/dev/null || true

  trap clean EXIT

  case "$1" in
  serveHtml)
    run="serveHtml"
    ;;
  fiction)
    run="FictionRequestHandler"
    ;;
  *)
    # source the configuration file and check if runner is defined
    [[ -z "$1" || ! -f "$1" ]] && {
      printf '%s\n' "please provide a file to source as the first argument..."
      exit 1
    }
    # source main file
    source "$1"
    type runner &>/dev/null || {
      printf '%s\n' "The source file need a function nammed runner which will be executed on each request..."
      exit 1
    }
    run="runner"
    ;;
  esac
  if "$HTTPS"; then
      kill -0 "$_pid" 2>/dev/null && kill -9 "$_pid"
      coproc https_proc {  exec -a "fiction" socat openssl-listen:"$HTTP_PORT",bind="$BIND_ADDRESS",verify=0,cert="$SSL_CERT",key="$SSL_KEY",reuseaddr,fork STDIO; }
      _pid="$https_proc_PID"
      local i=1;
      local headers=""
      while read -u ${https_proc[0]} data; do
        headers+="$data"
        if [[ "${#data}" == "1" ]]; then
          parseAndPrint <<<"$headers" >&${https_proc[1]}
          headers=""
          rm -rf "$serverTmpDir"
          serverTmpDir="$(mktemp -d)"
      fi
      done
      kill -9 "$_pid"
  else
    while :; do
    if [[ ! -d "$serverTmpDir" || -z "$serverTmpDir" ]]; then
      export serverTmpDir="$(mktemp -d)"
      TMPDIR="$serverTmpDir"
    fi
    # author tried to implement multi-connection support by using subshells in the background, but it's very ineffective to use "until ... do true", as it makes dozens of system calls to filesystem
        accept -b "${BIND_ADDRESS}" "${HTTP_PORT}" || {
        printf '%s\n' "Could not listen on ${BIND_ADDRESS}:${HTTP_PORT}"
        exit 1
        }
        
      printf -v TIME_FORMATTED '%(%d/%b/%Y:%H:%M:%S)T' -1
      printf -v TIME_SECONDS '%(%s)T' -1
      parseAndPrint <&${ACCEPT_FD} >&${ACCEPT_FD}
      exec {ACCEPT_FD}>&-

      # remove the temporary directory
      rm -rf "$serverTmpDir"
     
    _pid="$!"
  done
fi
}

# --- END OF https://github.com/dzove855/Bash-web-server/ ---
function getQuery() {
  [ -z "$1" ] && return
  IFS="=" read -r _ val <<<"${GET["$1"]}"
  echo "$val"
}

# HelperFns
function FictionServePath() {
  # FictionServePath <from> <to:fn> <as>
  echo "Added route: from '$1' to '$2' as '$3'"
  FictionRoute["$1"]="$2"
  FictionRouteContentType["$1"]="$3"
}

function FictionServeDynamicPath() {
  # FictionServePath <from> <to:fn> <as>
  echo "Added dynamic route: from '$1' to '$2' as '$3'"
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
    ${FictionRoute["${REQUEST_PATH}"]}
  elif [[ ${#FictionDynamicRoute[@]} > 0 ]]; then
    local matching_slugs=0
    IFS='/' read -ra path_keys <<< "${REQUEST_PATH#\/}";
    i=0
    for route in ${FictionDynamicRoute[@]}; do
      IFS=':' read route funcname <<< "$route"
      IFS='/' read -ra route_keys <<< "${route#\/}"
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
      ((matching_slugs > 0)) && $funcname
  done
  else
    httpSendStatus 404
    sendError "404 Page Not Found"
  fi
}

function FictionHttpServer() {
  # FictionHttpServer <port>
  local origaddress="$1"
  if [[ "$origaddress" =~ "https://" ]]; then
   HTTPS=true
   origaddress="${origaddress//https:\/\/}"
  elif [[ "$address" =~ "http://" ]]; then
   origaddress="${origaddress//http:\/\/}"
  fi
  IFS=':' read -r address port <<<"$origaddress"
  [ -z "$port" ] && { "$HTTPS" && port=443 || port=80; }
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
  if "${HTTPS:=false}"; then 
    [[ "$port" = 443 ]] &&  echo -e "\nServing your webserver at https://$address" || echo -e "\nServing your webserver at https://$address:$port" 
  else 
    [[ "$port" = 80 ]] &&  echo -e "\nServing your webserver at http://$address" || echo -e "\nServing your webserver at http://$address:$port"
  fi
  main fiction

}
