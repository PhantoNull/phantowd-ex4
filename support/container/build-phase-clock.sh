#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Sourced host-only diagnostics: no command wrapper, trap, timer or acceptance.

phantowd_phase_clock() {
    IFS=' ' read -r _phantowd_uptime _phantowd_idle < /proc/uptime || return 1
    _phantowd_seconds=${_phantowd_uptime%.*}
    _phantowd_fraction=${_phantowd_uptime#*.}
    case "$_phantowd_seconds" in ''|*[!0-9]*|0[0-9]*) return 1 ;; esac
    [ "${#_phantowd_seconds}" -le 10 ] || return 1
    case "$_phantowd_fraction" in [0-9][0-9]) ;; *) return 1 ;; esac
    # Prefix avoids interpreting a fractional 08/09 as shell octal.
    printf '%s\n' "$((_phantowd_seconds * 100 + 1$_phantowd_fraction - 100))"
}

phantowd_phase_sample() {
    _phantowd_sample=$(phantowd_phase_clock 2>/dev/null) || _phantowd_sample=unknown
    case "$_phantowd_sample" in ''|*[!0-9]*|0[0-9]*) _phantowd_sample=unknown ;; esac
    if [ "${#_phantowd_sample}" -gt 12 ]; then _phantowd_sample=unknown; fi
    printf '%s\n' "$_phantowd_sample"
}

phantowd_phase_begin() {
    if [ -n "${_phantowd_phase_label:-}" ]; then
        printf '%s\n' 'PHANTOWD_BUILD_PHASE_UNAVAILABLE reason=nested-begin qualifying=false' || :
        return 0
    fi
    case "${1:-}" in
        preflight|source-prepare|host-sdk|host-api|host-lab|target-build|legal-info|volume-probe|qemu-smoke|qemu-md|qemu-state|artifact-export|service-launcher|runtime-owner|runtime-loader|atomic-dispatch|samba-all|smart-staging|smart-report|smart-replay|samba-stage|samba-service|samba-native|samba-native-data|samba-candidate|samba-lifecycle|samba-fault|samba-data|samba-exit|samba-held|samba-file|samba-file-source|samba-pending|samba-pending-peer-exit|samba-pending-handle) ;;
        *)
            _phantowd_phase_label=
            printf '%s\n' 'PHANTOWD_BUILD_PHASE_UNAVAILABLE reason=invalid-label qualifying=false' || :
            return 0 ;;
    esac
    _phantowd_phase_label=$1
    _phantowd_phase_start=$(phantowd_phase_sample)
    _phantowd_clock=linux-uptime
    if [ "$_phantowd_phase_start" = unknown ]; then _phantowd_clock=unavailable; fi
    printf 'PHANTOWD_BUILD_PHASE_BEGIN phase=%s start_cs=%s clock=%s qualifying=false\n' \
        "$_phantowd_phase_label" "$_phantowd_phase_start" "$_phantowd_clock" || :
    return 0
}

phantowd_phase_end() {
    if [ -z "${_phantowd_phase_label:-}" ]; then
        printf '%s\n' 'PHANTOWD_BUILD_PHASE_UNAVAILABLE reason=unpaired-end qualifying=false' || :
        return 0
    fi
    _phantowd_end=$(phantowd_phase_sample)
    _phantowd_elapsed=unknown
    _phantowd_clock=unavailable
    if [ "${_phantowd_phase_start:-unknown}" != unknown ] && [ "$_phantowd_end" != unknown ] && \
        [ "$_phantowd_end" -ge "$_phantowd_phase_start" ]; then
        _phantowd_elapsed=$((_phantowd_end - _phantowd_phase_start))
        _phantowd_clock=linux-uptime
    fi
    _phantowd_status=${1:-unknown}
    case "$_phantowd_status" in
        ''|*[!0-9]*) _phantowd_status=unknown ;;
        *)
            if [ "${#_phantowd_status}" -gt 3 ] || [ "$_phantowd_status" -gt 255 ]; then
                _phantowd_status=unknown
            fi ;;
    esac
    printf 'PHANTOWD_BUILD_PHASE_END phase=%s elapsed_cs=%s command_status=%s clock=%s qualifying=false\n' \
        "$_phantowd_phase_label" "$_phantowd_elapsed" "$_phantowd_status" "$_phantowd_clock" || :
    _phantowd_phase_label=
    return 0
}
