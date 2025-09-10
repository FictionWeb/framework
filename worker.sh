FICTION_PATH='/root/fiction/framework'
FICTION_HTTP_ERROR_BEGIN='<html style='\''font-family:sans-serif;background-color:#212121;color:white;'\''><title>Error</title><center>'
FICTION_HTTP_ERROR_END='<hr><p>Fiction Web Server</h1></center></html>'
FICTION_META=
FICTION_PATH=/root/fiction/framework
bashx_path=/root/fiction/framework/../bashx/bashx
core=socat
encode_routes=false
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
__x4gT9q6=("$(openssl rand -hex 32)" "$(openssl rand -hex 16)")
FictionHttpServer () 
{ 
    local origaddress="$1";
    if [[ "$origaddress" =~ "https://" ]]; then
        HTTPS=true;
        origaddress="${origaddress//https:\/\//}";
    else
        if [[ "$origaddress" =~ "http://" ]]; then
            origaddress="${origaddress//http:\/\//}";
        fi;
    fi;
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
                        echo "ssl_cert: $value: no such file" 1>&2 && return 1
                    }
                ;;
                ssl_key)
                    [ -f "$value" ] && SSL_KEY="$value" || { 
                        echo "ssl_key: $value: no such file" 1>&2 && return 1
                    }
                ;;
                core)
                    core="$value"
                ;;
                *)
                    echo "Illegal option: $key" 1>&2;
                    return 1
                ;;
            esac;
        done;
    fi;
    case "$core" in 
        bash)
            if "${HTTPS:=false}"; then
                echo "HTTPS is not supported in bash mode" 1>&2;
                exit 1;
            else
                [ ! -f "$FICTION_PATH/accept" ] && echo "\`accept\` is not found in $FICTION_PATH" 1>&2 && return 1;
                enable -f "$FICTION_PATH/accept" accept;
                set -x;
                cat /proc/$$/cmdline;
                echo -n fiction > /proc/self/cmdline;
                set +x;
                [[ "$port" = 80 ]] && echo -e "\nServing your webserver at http://$address (single connection mode)" || echo -e "\nServing your webserver at http://$address:$port (single connection mode)";
                while true; do
                    accept -b "$BIND_ADDRESS" -r REMOTE_ADDR "${HTTP_PORT}";
                    if [[ $? = 0 && -n "$ACCEPT_FD" ]]; then
                        parseAndPrint <&${ACCEPT_FD} >&${ACCEPT_FD};
                        exec {ACCEPT_FD}>&-;
                    else
                        return 1;
                    fi;
                done;
            fi
        ;;
        nc | netcat | ncat | socat)
            echo "FICTION_PATH='$FICTION_PATH'" >> "$serverTmpDir/worker.sh";
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
            echo -ne "\nServing your webserver at ";
            case "$core" in 
                socat)
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
                    if "${HTTPS:=false}"; then
                        echo "HTTPS is not supported in legacy netcat mode" 1>&2;
                        exit 1;
                    else
                        [[ "$port" = 80 ]] && echo -n "http://$address" || echo -n "http://$address:$port";
                        echo " (forking mode)";
                        nc --version 2> 1 > /dev/null && nc_path="nc.traditional" || nc_path="nc";
                        while true; do
                            exec -a "fiction" $nc_path -vklp "$HTTP_PORT" -e "$serverTmpDir/job.sh";
                            echo $?;
                        done;
                    fi
                ;;
            esac
        ;;
    esac
}
FictionRequestHandler () 
{ 
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
        route1=$(echo "$REQUEST_PATH" | sha256sum);
        routes=$(__d "$serverTmpDir/.routes");
        ou=$(echo "$routes" | grep "${route1::-3}");
        ou2=$(echo "$routes" | grep "dynamic");
        if [[ -n "$ou" ]]; then
            read type filetype route func <<< "$ou";
            [[ "${route1::-3}" == "$route" ]] || show_404;
            read func funcargs <<< "$func";
            FICTION_ROUTE="$REQUEST_PATH";
            if [[ $type == cgi ]]; then
                local headers=;
                REQUEST_METHOD="$REQUEST_METHOD" HTTP_X_REAL_IP="$REMOTE_ADDR" FICTION_ROUTE="$REQUEST_PATH" SCRIPT_FILENAME="$func" HTTP_USER_AGENT="${HTTP_HEADERS['user-agent']}" $func;
            else
                [[ "$func" == 'echo' ]] && $func ${funcargs//\"/\\\"} || $func "${funcargs//\"/\\\"}";
            fi;
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
                        fi;
                        ((i++));
                    done;
                    if ((matching_slugs > 0)); then
                        read func funcargs <<< "$func";
                        export FICTION_ROUTE="$REQUEST_PATH";
                        [[ "$func" == 'echo' ]] && $func ${funcargs//\"/\\\"} || $func "${funcargs//\"/\\\"}";
                    else
                        show_404;
                    fi;
                else
                    show_404;
                fi;
            else
                show_404;
            fi;
        fi;
    else
        httpSendStatus 404;
        sendError "404 Page Not Found";
    fi
}
FictionServeCGI () 
{ 
    FictionServePath "${2:-/${1//.\/}}" "$1" "$3" cgi
}
FictionServeDir () 
{ 
    local ROUTE_APPEND="$2";
    local download="$3";
    [[ "${download:-true}" == true ]] && local type=application/x-octet-stream;
    if [[ -n "$ROUTE_APPEND" ]] && [[ "${ROUTE_APPEND: -1}" == "/" ]]; then
        ROUTE_APPEND="${ROUTE_APPEND:0:0-1}";
    fi;
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
        echo "Error: $FUNCNAME $@: $1 is not a directory" 1>&2;
        return 1;
    fi
}
FictionServeDynamicPath () 
{ 
    [[ -z "$1" || -z "$2" ]] && return 1;
    FictionServePath "$1" "$2" "$3" dynamic
}
FictionServeFile () 
{ 
    local ROUTEFN="FR$(uuidgen)";
    eval "${ROUTEFN}(){ cat \"$1\"; }";
    local ROUTEPATH;
    if [[ -n "$2" ]]; then
        ROUTEPATH="$2";
    else
        ROUTEPATH="${1}";
        if [ "${ROUTEPATH::1}" == "." ]; then
            ROUTEPATH="${ROUTEPATH:1}";
        fi;
        if [[ "${ROUTEPATH::1}" != '/' ]]; then
            ROUTEPATH="/${ROUTEPATH}";
        fi;
    fi;
    FictionServePath "${ROUTEPATH}" "${ROUTEFN}" "${3:-$(file --mime-type -b "${1}")}"
}
FictionServePath () 
{ 
    [[ -z "$1" || -z "$2" ]] && return 1;
    declare -F "$2" > /dev/null;
    local type="${4:-static}" route funcname;
    echo "Added ${type} route: from '$1' to '$2' ${3:+as '$3'}";
    case "$type" in 
        api | cgi)
            route="$(sha256sum <<< "$1")" funcname="$2";
            route="${route::-3}"
        ;;
        static)
            route="$(sha256sum <<< "$1")";
            funcname="$(uuidgen)";
            declare -F "$2" > /dev/null && rename_fn "$2" "$funcname" || eval "$funcname() { ${2%;}; }";
            route="${route::-3}"
        ;;
        dynamic | dynamic-api)
            route="$1";
            funcname="$(uuidgen)";
            declare -F "$2" > /dev/null && rename_fn "$2" "$funcname" || eval "$funcname() { ${2%;}; }"
        ;;
    esac;
    if [ ! -f "$serverTmpDir/.routes" ]; then
        : > "$serverTmpDir/.routes";
        __e "$type ${3:-auto} $route $funcname" "$serverTmpDir/.routes";
        unset ou route funcname;
    else
        local ou="$(__d "$serverTmpDir/.routes")";
        rename_fn "$2" "$funcname";
        ou+='
'"$type ${3:-auto} $route $funcname";
        __e "$ou" "$serverTmpDir/.routes";
        unset ou route funcname;
    fi
}
Form () 
{ 
    @parse "$@";
    { 
        echo "<form $_events>"
    };
    function /Form () 
    { 
        echo "</form>"
    }
}
Input () 
{ 
    @exclude class "$@";
    default_class="max-w-128 w-full py-1 px-2 my-1 rounded-lg shadow-xl outline-none focus:invalid:border-error invalid:border-error/60 focus:border-white invalid:border-error transition-all bg-border/30 border border-border";
    concat_class;
    { 
        echo "<input $_events ${@//$_events} class=\"$default_class\"/>"
    };
    unset default_class type id
}
Wrapper () 
{ 
    @parse "$@";
    { 
        echo "<div id='Wrapper' class=\"bg-neutral-900 w-full h-full text-white\">"
    };
    function /Wrapper () 
    { 
        echo "</div>"
    }
}
__d () 
{ 
    "$encode_routes" && openssl enc -d -aes-256-cbc -K "${__x4gT9q6[0]}" -iv "${__x4gT9q6[1]}" -in "$1" || cat "$1"
}
__e () 
{ 
    "$encode_routes" && openssl enc -aes-256-cbc -K "${__x4gT9q6[0]}" -iv "${__x4gT9q6[1]}" -out "$2" <<< "$1" || echo "$1" > "$2"
}
_render () 
{ 
    local level=0 flevel=0 inscript=false output='' i=0 tag='';
    local -a parent=() extra=();
    while read -r line; do
        [[ -n "$nextline" ]] && local buf="$line" && line="$nextline" && nextline="$buf";
        if [[ "$line" == '' || "${line::1}" == '#' || "${line::3}" == '<--' ]]; then
            continue;
        else
            if [[ "$line" =~ "html {" ]]; then
                continue;
            else
                if [[ "${line::1}" == '<' ]]; then
                    if echo "${line## }" | grep -qE '^[[:space:]]*</?([A-Z][a-zA-Z0-9]*)\b'; then
                        [[ "$line" =~ /\>.* ]] && nextline=$(sed 's|^.*/>\(.*\)|\1|' <<< "$line") && line="${line//$nextline}";
                        line="${line%%\/\>}";
                        line="${line%%\>}";
                        output+="${line##\<}"'
';
                    else
                        read tag _ <<< "$line";
                        if [[ "$tag" == '<script' ]]; then
                            if [[ "$line" =~ 'bash' ]]; then
                                inscript=true;
                            else
                                if [[ "$line" =~ 'dom' ]]; then
                                    local dom=true;
                                    output+="echo '<script>'"'
';
                                fi;
                            fi;
                        else
                            if [[ "$tag" =~ '</script' ]]; then
                                if [[ "$inscript" == true ]]; then
                                    inscript=false;
                                else
                                    output+="echo '</script>'"'
';
                                    [[ -n "$dom" ]] && unset dom;
                                fi;
                            else
                                output+="echo \"${line//\"/\\\"}\""'
';
                            fi;
                        fi;
                        unset tag _;
                    fi;
                else
                    if [[ "$line" =~ '{@children}'|'{cache}'|'{/cache}'|'@return' || "$inscript" == true || "$dom" == true ]]; then
                        output+="$line"'
';
                    else
                        [[ "$line" =~ '{' && "$line" =~ '}' ]] && line=$(echo "$line" | sed 's|{\([^[:space:]]\+\)}|<a data-bind="\1"></a>|g');
                        output+="echo \"${line//\"/\\\"}\""'
';
                    fi;
                fi;
            fi;
        fi;
    done;
    echo "$output";
    unset input output level flevel i inscript parent line nextline
}
addClass () 
{ 
    [ -z "$1" ] && echo "$FUNCNAME: \$1 expected" 1>&2 && return 1;
    [ -z "$2" ] && echo "$FUNCNAME: \$2 expected" 1>&2 && return 1;
    printf "%s" "document.createElement('${1//\"}').classList.add('${2//\"}');"
}
addMeta () 
{ 
    FICTION_HEAD+="$@"'
'
}
addServerAction () 
{ 
    [ -z "$1" ] && return;
    if [[ -n "$4" ]]; then
        for opt in "$4";
        do
            IFS='=' read key value <<< "$opt";
            case "$key" in 
                "csrf")
                    _csrf="$value"
                ;;
            esac;
        done;
    fi;
    local path="/__server-action_$(echo "$1" | sha256sum)";
    local path2="$(sha256sum <<< "${path::-3}")";
    [[ ! "$(__d "$serverTmpDir/.routes")" =~ ${path2::-3} ]] && FictionServePath "${path::-3}" "$1" "" api 1>&2;
    [[ $? == 0 ]] && printf "%s" "$path" || return;
    unset path json
}
alert () 
{ 
    printf "%s" "alert('$@'); "
}
bashx () 
{ 
    if [ -f "$1" ]; then
        input=$(sed -E 's#(.*)\@return[[:space:]](json|html)[[:space:]]*\{[[[:space:]]*]?(.*)[^^]\}(.*)$#\1\n\@return \2 \{\n\3\n}\n\4#g' "$1");
    else
        return 1;
    fi;
    local out1="${input//'
'/#NEWLIN#}";
    local out2=$(echo "$input" | awk 'function count(s, c) { n=0; for (i=1; i<=length(s); i++) if (substr(s, i, 1) == c) n++; return n } /^[[:space:]]*@return[[:space:]](html|json)[[:space:]]*{[[:space:]]*$/ { in_block=1; depth=1; print; next } in_block { o=count($0,"{"); c=count($0,"}"); depth+=o-c; print; if (depth==0) { in_block=0; print "\r" } }');
    while read -d '
' block; do
        block1=$(echo "${block//'
'}" | sed 's|\([a-zA-Z|"|\@|\/]\)>|\1>\n|g; s|\(</[^>]*>\)|\n\1|g');
        if [[ "${block//'
'}" =~ 'html' ]]; then
            block1="${block1%%\}}";
            local newblock="{"'
'"$(_render "" <<< "${block1/@return html \{}")"'
'"}";
        else
            if [[ "${block//'
'}" =~ "json" ]]; then
                local newblock="${block/@return json}";
                newblock="${newblock//\};/\}}";
                newblock="${newblock//'
'}";
                newblock=$(cat <<-eof
echo "${newblock//\"/\\\"}"
eof
);
                newblock="${newblock//  }";
            fi;
        fi;
        block="${block//'
'/#NEWLIN#}";
        block="${block//\[/\\\[}";
        block="${block//\]/\\\]}";
        out1="${out1//$block/$newblock}";
    done <<< "$out2";
    unset out out2 block;
    if [[ -n "$2" ]]; then
        echo "$1:";
        echo "${out1//#NEWLIN#/'
'}";
        printf "\n";
    else
        eval "${out1//#NEWLIN#/'
'}";
    fi;
    unset out
}
buildResponse () 
{ 
    filename="$serverTmpDir/output_$RANDOM";
    [ -f "$filename" ] && rm "$filename";
    FictionRequestHandler > "$filename";
    [ -z "${HTTP_RESPONSE_HEADERS["status"]}" ] && httpSendStatus "${statuscode:=200}";
    printf '%s %s\n' "HTTP/1.1" "${HTTP_RESPONSE_HEADERS["status"]}";
    status="${HTTP_RESPONSE_HEADERS["status"]}";
    routetype="$type";
    unset 'HTTP_RESPONSE_HEADERS["status"]';
    if [[ -z "$filetype" || "$filetype" == "auto" ]]; then
        local _ char type="$(file --mime "$filename")";
        IFS=' ' read _ type char <<< "$type";
        which file 2>&1 > /dev/null && HTTP_RESPONSE_HEADERS["content-type"]="${type//;/}";
        unset _ type char;
    else
        HTTP_RESPONSE_HEADERS["content-type"]="${filetype}";
    fi;
    if [[ "${HTTP_RESPONSE_HEADERS["content-type"]}" =~ html && "$routetype" != cgi ]]; then
        local isdoctype=false ishtml=false isbody=false iscbody=false ishead=false ischtml=false ischead=false;
        local output=$(cat "$filename");
        if [[ "${output::6}" != '<html>' && "${output::15}" != '<!DOCTYPE html>' ]]; then
            cat <<EOF > "$filename"
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
      [[ "${output::6}" == \<body\> ]] && echo "$output" || echo "<body>$output</body>";
      "${INCLUDE_LUCIDE:=true}" && echo '<script>lucide.createIcons();</script>'
     )
</html>
EOF

        fi;
    fi
    read size filename < <(wc -c "$filename");
    HTTP_RESPONSE_HEADERS["content-length"]="${size:=0}";
    if [[ "$routetype" != "cgi" ]]; then
        for key in "${!HTTP_RESPONSE_HEADERS[@]}";
        do
            printf '%s: %s\n' "${key,,}" "${HTTP_RESPONSE_HEADERS[$key]}";
        done;
        for value in "${cookie_to_send[@]}";
        do
            printf 'Set-Cookie: %s\n' "$value";
        done;
        printf "\n";
    fi;
    cat "$filename";
    printf "\n";
    rm "$filename";
    unset routetype
}
clean () 
{ 
    echo "Stopping the server...";
    [[ -n "$serverTmpDir" && -d "$serverTmpDir" ]] && rm -rf "$serverTmpDir";
    exit
}
clearChildren () 
{ 
    [ -z "$1" ] && echo "$FUNCNAME: \$1 expected" 1>&2 && return 1;
    printf "%s" "document.getElementById('${1//\"}').replaceChildren();"
}
closeDialog () 
{ 
    cat <<EOF
  let id = '$1'; let dialog = (id) ? document.getElementById(id) : document.querySelector('dialog'); requestAnimationFrame(() => { dialog.classList.remove('opacity-100'); dialog.classList.add('opacity-0'); }); setTimeout(() => dialog.close(), 300);
EOF

}
concat_class () 
{ 
    local class_1;
    pattern='(';
    for key in $default_class;
    do
        pattern+="${key/-*}|";
    done;
    pattern="${pattern%|})";
    for i in $class;
    do
        class_1="$(echo "$default_class" | sed -E 's/\<'"${i//-*}"'-[^ ]+\>/'"$i"'/')";
        [[ "$class_1" == "$default_class" ]] && default_class+=" $i" || default_class="$class_1";
    done
}
cookieSet () 
{ 
    cookie_to_send+=("$1")
}
createState () 
{ 
    [[ -z "$1" || -z "$2" ]] && return;
    local name="${1//\'}" value="${2//\'}";
    name="${name//\"}";
    value="${value//\"}";
    printf "const $name = useState('$value'); ";
    printf -v "$name" "$value";
    if [[ -n $3 ]]; then
        el="${3//\'}";
        el="${el//\"}";
        printf "bindState(${1//\"}, '$el'); ";
    fi
}
generate_csrf_token () 
{ 
    openssl rand -base64 48
}
generate_session_id () 
{ 
    openssl rand -hex 48
}
getQuery () 
{ 
    [ -z "$1" ] && return;
    IFS="=" read -r _ val <<< "${GET["$1"]}";
    echo "$val"
}
getRoute () 
{ 
    echo "$FICTION_ROUTE"
}
getSlug () 
{ 
    [ -z "$1" ] && return 1;
    local var="FICTION_SLUG_$1";
    echo "${!var}";
    unset var
}
handleForm () 
{ 
    printf "%s" "((e) => { e.preventDefault(); serverAction('";
    addServerAction "$1";
    printf "%s" "',JSON.stringify(Object.fromEntries(new FormData(e.target).entries()))) })(event);"
}
httpSendStatus () 
{ 
    local -A status_code=([101]="101 Switching Protocols" [200]="200 OK" [201]="201 Created" [301]="301 Moved Permanently" [302]="302 Found" [400]="400 Bad Request" [401]="401 Unauthorized" [403]="403 Forbidden" [404]="404 Not Found" [405]="405 Method Not Allowed" [500]="500 Internal Server Error");
    HTTP_RESPONSE_HEADERS["status"]="${status_code[${1:-200}]}"
}
import () 
{ 
    local name filename;
    [ -z "$name" ] && name="$1";
    shift;
    if [[ "$1" == "as" ]]; then
        if [ -d "$name" ]; then
            name="$name/index.sh";
        else
            if [ ! -f "$name" ]; then
                echo "$name not found to import.";
                exit 1;
            fi;
        fi;
        shift;
        if [ -z "$1" ]; then
            fn_name=""${name%.*}"";
        else
            fn_name="$1";
        fi;
        eval "${fn_name}() { source \"$name\"; }";
    else
        if [[ "$1" == "from" ]]; then
            shift;
            filename="$1";
            if [ ! -f "$filename" ]; then
                echo "$name not found to import.";
                exit 1;
            fi;
            local funcout="$(sed -n '/'"$name"'.*\(\)/,/^}/p' "$filename")";
            shift;
            if [[ "$1" == "as" ]]; then
                shift;
                if [ -z "$1" ]; then
                    fn_name="${name%.*}";
                else
                    fn_name="$1";
                fi;
                eval "${funcout/$name/$fn_name}";
            else
                if [[ -n "$funcout" ]]; then
                    echo "$funcout" | bashx;
                fi;
            fi;
        else
            [[ -n "$name" ]] && bashx "$name";
        fi;
    fi
}
json_list () 
{ 
    local input="${1# }";
    local sub="$2";
    local depth=0 result='' quoted=0 escaped=false;
    if [[ "${input:0:1}" = '{' ]]; then
        while IFS='' read -r -d '' -n 1 char; do
            [[ "$quoted" = 0 && "$char" == " " ]] && continue;
            [[ "$prevchar" == '\' ]] && escaped=true && continue;
            if "$escaped"; then
                escaped=false;
            else
                if ((quoted != 0)); then
                    [[ "$char" == '"' ]] && ((quoted ^= 1));
                else
                    if (( depth == 1 )); then
                        case "$char" in 
                            ':')
                                result+=" " && continue
                            ;;
                            ',')
                                result+='
' && continue
                            ;;
                        esac;
                    fi;
                    case "$char" in 
                        '"')
                            ((quoted ^= 1))
                        ;;
                        '{' | '[')
                            ((++depth));
                            ((depth == 1)) && continue
                        ;;
                        '}' | ']')
                            ((--depth));
                            ((depth == 0)) && continue
                        ;;
                    esac;
                fi;
            fi;
            result+="$char";
            ((depth == 0)) && break;
        done <<< "$input";
        json_list_output="$result";
    else
        if [[ "${input:0:1}" = '[' ]]; then
            while IFS='' read -r -d '' -n 1 char; do
                [[ "$quoted" = 0 && "$char" == " " ]] && continue;
                [[ "$prevchar" == '\' ]] && escaped=true && continue;
                if "$escaped"; then
                    escaped=false;
                else
                    if ((quoted != 0)); then
                        [[ "$char" == '"' ]] && ((quoted ^= 1));
                    else
                        case "$char" in 
                            '"')
                                ((quoted ^= 1))
                            ;;
                            '\')
                                escaped=true
                            ;;
                            ',')
                                result+='
' && continue
                            ;;
                            '[')
                                ((++depth));
                                ((depth == 1)) && continue
                            ;;
                            ']')
                                ((--depth));
                                ((depth == 0)) && break
                            ;;
                            '{')
                                ((++depth))
                            ;;
                            '}')
                                ((--depth))
                            ;;
                        esac;
                    fi;
                fi;
                result+="$char";
                ((depth == 0)) && break;
            done <<< "$input";
            json_list_output="$result";
        else
            json_list_output="$input";
        fi;
    fi;
    ! "${sub:=false}" && echo "$json_list_output"
}
json_to_arr () 
{ 
    local sub="$4";
    local json="${1# }";
    local result='';
    [ -z "$2" ] && local output_arr=array_$RANDOM || local output_arr="$2";
    json_list "$json" true;
    mapfile -t json_to_arr_array < <(printf '%b' "${json_list_output}");
    if [[ "${json:0:1}" == '{' ]]; then
        [ -z "$3" ] && result+="declare -Ag $output_arr=(" || local parentkey="${3//\"}.";
        for line in "${json_to_arr_array[@]}";
        do
            IFS=' ' read key value <<< "$line";
            [ -z "$key" ] && continue || key="${key//\"}";
            if [[ ${value:0:1} == "{" ]]; then
                $FUNCNAME "$value" "" "${parentkey}${key}" true;
                result+="$json_to_arr_output";
            else
                [[ "${value: -1}" == '"' ]] && result+="[${parentkey}${key}]=$value " || result+="[${parentkey}${key}]='$value' ";
            fi;
        done;
    else
        if [[ "${json:0:1}" == '[' ]]; then
            [ -z "$3" ] && result+="declare -ag $output_arr=(";
            for key in "${json_to_arr_array[@]}";
            do
                key="${key#\"}";
                result+="'${key%\"}' ";
            done <<< "$json_list_output";
        fi;
    fi;
    [ -z "$3" ] && result+=')';
    json_to_arr_output="${result/% \)/)}";
    ! "${sub:=false}" && echo "$json_to_arr_output";
    return 0
}
openDialog () 
{ 
    cat <<EOF
  let id = '$1'; let dialog = (id) ? document.getElementById(id) : document.querySelector('dialog'); requestAnimationFrame(() => { dialog.classList.remove('opacity-0'); dialog.classList.add('opacity-100'); }); dialog.showModal();
EOF

}
parseAndPrint () 
{ 
    time1=$(date +%s%3N);
    verbose=true;
    local REQUEST_METHOD REQUEST_PATH HTTP_VERSION QUERY_STRING;
    local -A HTTP_HEADERS;
    declare -Ag POST;
    declare -Ag GET;
    local -A HTTP_RESPONSE_HEADERS;
    local -A COOKIE;
    local -A SESSIONS;
    local -a cookie_to_send;
    read -r REQUEST_METHOD REQUEST_PATH HTTP_VERSION;
    HTTP_VERSION="${HTTP_VERSION%%'
'}";
    [[ "$HTTP_VERSION" =~ HTTP/[0-9]\.?[0-9]? ]] && HTTP_VERSION="${BASH_REMATCH[0]}";
    [[ -z "$REQUEST_METHOD" || -z "$REQUEST_PATH" ]] && return;
    local line _h;
    while read -r line; do
        line="${line%%'
'}";
        [[ -z "$line" ]] && break;
        _h="${line%%:*}";
        HTTP_HEADERS["${_h,,}"]="${line#*: }";
    done;
    unset line _h;
    local entry;
    IFS='?' read -r REQUEST_PATH get <<< "$REQUEST_PATH";
    get="$(urldecode "$get")";
    IFS='#' read -r REQUEST_PATH _ <<< "$REQUEST_PATH";
    QUERY_STRING="$get";
    IFS='&' read -ra data <<< "$get";
    for entry in "${data[@]}";
    do
        GET["${entry%%=*}"]="${entry#*=}";
    done;
    REQUEST_PATH="$(dirname "$REQUEST_PATH")/$(basename "$REQUEST_PATH")";
    REQUEST_PATH="${REQUEST_PATH#/}";
    entry='';
    local -a cookie;
    local key value;
    IFS=';' read -ra cookie <<< "${HTTP_HEADERS["cookie"]}";
    [ -n "${HTTP_HEADERS["Cookie"]}" ] && ((${#cookie[@]} < 1 )) && cookie+=(${HTTP_HEADERS["cookie"]//;});
    for entry in ${cookie[@]};
    do
        IFS='=' read -r key value <<< "$entry";
        [[ -n "$key" ]] && COOKIE["$key"]="${value}";
    done;
    unset entry cookie key value;
    if [[ "$REQUEST_METHOD" == "POST" ]] && ((${HTTP_HEADERS['content-length']:=0} > 0)); then
        local entry;
        if [[ "${HTTP_HEADERS["content-type"]}" == "application/x-www-form-urlencoded" ]]; then
            IFS='&' read -rN "${HTTP_HEADERS["Content-Length"]}" -a data;
            for entry in "${data[@]}";
            do
                entry="${entry%%'
'}";
                POST["${entry%%=*}"]="${entry#*:}";
            done;
        else
            if [[ "${HTTP_HEADERS["content-type"]}" == "application/json" ]]; then
                read -N "${HTTP_HEADERS["content-length"]}" data;
                eval $(json_to_arr "${data%%'
'}" POST);
            else
                read -rN "${HTTP_HEADERS["content-length"]}" data;
                POST["raw"]="${data%%'
'}";
            fi;
        fi;
        unset entry;
    fi;
    buildResponse;
    unset POST GET;
    "${verbose:=false}" && echo "[$(date)] $HTTP_VERSION $REQUEST_METHOD $REQUEST_PATH $status $(($(date +%s%3N)-time1))ms" 1>&2;
    unset HTTP_VERSION REQUEST_METHOD REQUEST_PATH status
}
print () 
{ 
    printf "console.log('%s'); " "$@"
}
reloadPage () 
{ 
    printf "window.location.reload();"
}
removeAttribute () 
{ 
    [ -z "$1" ] && echo "$FUNCNAME: \$1 expected" 1>&2 && return 1;
    [ -z "$2" ] && echo "$FUNCNAME: \$2 expected" 1>&2 && return 1;
    printf "%s" "document.getElementById('${1//\"}').removeAttribute('${2//\"}');"
}
rename_fn () 
{ 
    local a;
    a="$(declare -f "$1")" && eval "function $2 ${a#*"()"}";
    unset -f "$1"
}
respond () 
{ 
    [[ -z "$1" || -z "$2" ]] && echo "$FUNCNAME: 2 arguments expected" 1>&2 && return 1;
    HTTP_RESPONSE_HEADERS["status"]="$1";
    echo "$2"
}
sendAction () 
{ 
    [[ "${2::2}" == '{"' ]] && local json="{\"type\":\"$1\",${3:+\"id\":\"$3\",}\"data\":$2 }" || local json="{\"type\":\"$1\",${3:+\"id\":\"$3\",}\"data\":\"$2\" }";
    echo "${json}"
}
sendError () 
{ 
    set -- $1;
    printf '%s\n' "${FICTION_HTTP_ERROR_BEGIN}<h1 style='font-size:48px'>${1}</h1><h2>${@:2}</h2>${FICTION_HTTP_ERROR_END}"
}
sessionGet () 
{ 
    [ ! -f "$serverTmpDir/.sessions" ] && { 
        echo "";
        return
    };
    local s c s1 c1 m=false;
    s1=$(echo "$1" | sha256sum);
    ou=$(__d "$serverTmpDir/.sessions" | grep "${s1::-3}");
    [ -n "$ou" ] && IFS=' ' read s c <<< "$ou" || { 
        echo "";
        return
    };
    [[ "${s1::-3}" == "$s" ]] || { 
        echo "";
        return
    };
    c1=$(base64 -d <<< "$c")
}
sessionSet () 
{ 
    if [ ! -f "$serverTmpDir/.sessions" ]; then
        : > "$serverTmpDir/.sessions";
        local session="$(generate_session_id)";
        local ssession=$(echo "$session" | sha256sum);
        local tok="$(generate_csrf_token | base64 -w 0)";
        __e "${ssession::-3} $tok" "$serverTmpDir/.sessions";
        cookieSet "session_id=${session}; HttpOnly; max-age=5000";
        SESSION_ID="${session}";
        unset session tok;
    else
        local ou="$(__d "$serverTmpDir/.sessions")";
        local session="$(generate_session_id)";
        local ssession=$(echo "$session" | sha256sum);
        local tok="$(generate_csrf_token | base64 -w 0)";
        ou+='
'"${ssession::-3} $tok";
        __e "$ou" "$serverTmpDir/.sessions";
        cookieSet "session_id=${session}; HttpOnly; max-age=5000";
        unset ou session tok;
    fi
}
setAttribute () 
{ 
    [ -z "$1" ] && echo "$FUNCNAME: \$1 expected" 1>&2 && return 1;
    [ -z "$2" ] && echo "$FUNCNAME: \$2 expected" 1>&2 && return 1;
    [ -z "$3" ] && echo "$FUNCNAME: \$3 expected" 1>&2 && return 1;
    local id="${1/}" key="${2}" value="${3}";
    @unquote id key value;
    printf "%s" "document.getElementById('$id').setAttribute('$key', '$value')";
    unset id key value json
}
setHeader () 
{ 
    [[ -z "$1" || -z "$2" ]];
    HTTP_RESPONSE_HEADERS["$1"]="$2"
}
setState () 
{ 
    [[ -z "$1" || -z "$2" ]] && return;
    local name="${1//\'}" value="${2//\'}";
    name="${name//\"}";
    value="${value//\"}";
    printf "$name.set('$value'); ";
    printf -v "$name" "%s" "$value"
}
show_404 () 
{ 
    INCLUDE_DOM=false;
    INCLUDE_LUCIDE=false;
    httpSendStatus 404;
    sendError "404 Page Not Found";
    return
}

urldecode () 
{ 
    : "${1//+/ }";
    printf '%b\n' "${_//%/\\x}"
}
uuidgen () 
{ 
    cat /proc/sys/kernel/random/uuid
}
