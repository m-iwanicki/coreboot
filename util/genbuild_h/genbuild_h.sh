#!/usr/bin/env sh
#
# SPDX-License-Identifier: GPL-2.0-only

DATE=""
GITREV=""
TIMESOURCE=""
XGCCPATH="${XGCCPATH:-util/crossgcc/xgcc/bin/}"

export LANG=C
export LC_ALL=C
export TZ=UTC0

XCOMPILE=$1

if [ -z "$XCOMPILE" ] || [ "$1" = "--help" ]; then
	echo "usage: $0 <xcompile>" >&2
	exit 1
fi

# $1: format string
get_git_head_data() {
	LANG= git log --no-show-signature -1 --abbrev=10 --format="format:$1" 2>/dev/null || \
	LANG= git log -1 --abbrev=10 --format="format:$1"
}

if [ "${BUILD_TIMELESS}" = "1" ]; then
	GITREV=Timeless
	TIMESOURCE="fixed"
	DATE=0
elif [ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" = "true" ]; then
	GITREV=$(get_git_head_data %h)
	TIMESOURCE=git
	DATE=$(get_git_head_data %ct)
else
	GITREV=Unknown
	TIMESOURCE="date"
	DATE=$(LANG= LC_ALL=C TZ=UTC0 date +%s)
fi

our_date() {
case $(uname) in
NetBSD|OpenBSD|DragonFly|FreeBSD|Darwin)
	date -r $1 $2
	;;
*)
	date -d @$1 $2
esac
}

# Look for IASL in XGCCPATH and xcompile.  Unfortunately,
# xcompile isn't available on the first build.
# If neither of those gives a valid iasl, check the path.
IASL="${XGCCPATH}iasl"
eval $(grep ^IASL:= "$XCOMPILE" 2>/dev/null | sed s,:=,=,)
if [ ! -x "${IASL}" ]; then
	IASL=$(command -v iasl)
fi
IASLVERSION="$(${IASL} -v | grep version | sed 's/.*version //')" >/dev/null

#Print out the information that goes into build.h
printf "/* build system definitions (autogenerated) */\n"
printf "#ifndef __BUILD_H\n"
printf "#define __BUILD_H\n\n"
printf "#define COREBOOT_VERSION %s\n" "\"$KERNELVERSION\""

#See if the build is running in a git repo and the git command is available
printf "/* timesource: $TIMESOURCE */\n"

printf "#define DASHARO_VERSION \"%s\"\n" "$DASHARO_VERSION"
printf "#define DASHARO_MAJOR_VERSION %d\\n" "$DASHARO_MAJOR_VERSION"
printf "#define DASHARO_MINOR_VERSION %d\\n" "$DASHARO_MINOR_VERSION"
printf "#define DASHARO_PATCH_VERSION %d\\n" "$DASHARO_PATCH_VERSION"

printf "#define COREBOOT_VERSION_TIMESTAMP $DATE\n"
printf "#define COREBOOT_ORIGIN_GIT_REVISION \"$GITREV\"\n"

printf "#define COREBOOT_EXTRA_VERSION \"%s\"\n" "$COREBOOT_EXTRA_VERSION"
printf "#define COREBOOT_MAJOR_VERSION %d\n#define COREBOOT_MINOR_VERSION %d\n" `git describe --match [0-9].[0-9]* | sed 's/\([0-9]\)\.\([0-9][0-9]*\).*/\1 \2/'`
printf "#define COREBOOT_BUILD \"$(our_date "$DATE")\"\n"
printf "#define COREBOOT_BUILD_YEAR_BCD 0x$(our_date "$DATE" +%y)\n"
printf "#define COREBOOT_BUILD_MONTH_BCD 0x$(our_date "$DATE" +%m)\n"
printf "#define COREBOOT_BUILD_DAY_BCD 0x$(our_date "$DATE" +%d)\n"
printf "#define COREBOOT_BUILD_WEEKDAY_BCD 0x$(our_date "$DATE" +%w)\n"
printf "#define COREBOOT_BUILD_EPOCH \"$(our_date "$DATE" +%s)\"\n"
printf "#define COREBOOT_DMI_DATE \"$(our_date "$DATE" +%m/%d/%Y)\"\n"
printf "\n"
printf "#define COREBOOT_COMPILE_TIME \"$(our_date "$DATE" +%T)\"\n"
printf "#define ASL_VERSION 0x%d\n" "${IASLVERSION}"
printf "#endif\n"
