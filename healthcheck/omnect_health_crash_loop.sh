#!/bin/sh
#

. healthchecklib.sh

CRASH_LOOP_RESTART_THRESHOLD=3

# prints crash-looping services to stdout
function find_crash_loops() {
    local unit props active sub nrestarts found="" units

    units=$(systemctl list-units --all --type=service --no-legend --plain | awk '{print $1}')
    if [ -z "${units}" ]; then
        echo " failed to list services"
        return
    fi

    for unit in ${units}; do
        props=$(systemctl show "${unit}" -p ActiveState,SubState,NRestarts 2>/dev/null) || continue
        active=$(echo "${props}" | sed -n 's/^ActiveState=//p')
        sub=$(echo "${props}" | sed -n 's/^SubState=//p')
        nrestarts=$(echo "${props}" | sed -n 's/^NRestarts=//p')

        # the point-in-time auto-restart branch is deliberately more sensitive
        # than the update validation rule in omnect-device-service: a red
        # health rating is cheap, a validation rollback is not
        if [ "${active}" = "activating" ] && [ "${sub}" = "auto-restart" ]; then
            found="${found} ${unit}(auto-restart)"
        elif [ -n "${nrestarts}" ] && [ "${nrestarts}" -ge "${CRASH_LOOP_RESTART_THRESHOLD}" ] && [ "${active}" != "active" ]; then
            found="${found} ${unit}(NRestarts=${nrestarts})"
        fi
    done

    echo "${found}"
}

function do_check() {
    local found rating=0

    found=$(find_crash_loops)
    [ -z "${found}" ] || rating=2
    print_rating ${rating} crash_loop "$ME"
    do_rate ${rating}
    return ${rating}
}

function do_get_infos() {
    local found rating=0

    found=$(find_crash_loops)
    [ -z "${found}" ] || rating=2
    print_info_header "${ME}" "${rating}"
    [ -z "${found}" ] || echo "crash-looping services:${found}"
    return ${rating}
}

command="${1:-check}"
[ "$1" ] && shift
check_command_arg "$command"

case "$command" in
    check)
	do_check "$@"
	retval=$?
	;;
    get-infos)
	do_get_infos "$@"
	retval=$?
	;;
esac

exit $retval
