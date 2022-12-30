#!/bin/bash
#
# Create a script to recreate the specified file in a different place.
# (pasta stands for *PAST*eable *A*rchive)
#
# Requirements:
#  for this script:
#    - bash, gzip, base64
#
# for the generated script:
#    - Bourne shell from UNIX v7 or later
#    - OpenSSL with base64, or
#      base64 from GNU coreutils, or
#      base64 from BSD
#    - gunzip
#
# v2 enhancements:
# ----------------
#  * work around ~20 year old bug in the Almquist shell and descendants
#  * do not depend on external shell libraries anymore
#  * more documentation
#  * support XZ and zopfli compression
#  * support ASCII85 and Base91 encoding
#
set -eu
quit(){
            echo "$*" >&2
            exit 1
}

usage(){
cat<<EOF
Usage: $0 [OPTION]... [FILE] [OUTFILE]

Create a 7-bit clean *past*eable *a*rchive
OUTFILE is optional

  -p     Recreate file permissions
  -P     Recreate file at same path with same permissions (implies -p)
  -v     go viral!
  -z     zopfli compression (output compatible with gzip)
  -x     XZ compression
  -o     Optimal compression. Automatically choose best method
  -Z     old 'compress'
  -s     Shorter script, but less portable (GNU tools only)
  -6     Base64 encoding (default)
  -9     Base91 encoding
  -a     Ascii85 encoding
  -w N   wrap after N characters (default $WIDTH)
  -c     put output into clipboard
  -f     aa ('ascii armor') encoding
EOF
exit 0
}

# default options can be specified in PASTA env
[ "${PASTA-}" ] && set -- $PASTA "$@"
WIDTH=78
ENCODE="(openssl base64 2>&-||base64)"
# long option '--decode' needed for compatibility with FreeBSD base64
# (also used in MacOS X)
DECODE="(openssl base64 -d 2>&-||base64 --decode)"
COMPRESS="gzip -cn9"
DECOMPRESS="gunzip"
PERM=''
REC=''
EXTRA=''
CLIP=''
OPTC=''
BASE64=1
SELF=''
AA=''
while getopts "w:sxaz9pcoZh6rPvf" opt; do
            case $opt in
            o)
                        OPTC=1
                        ;;
            c)
                        CLIP=1
                        ;;
            p)
                        PERM=1
                        ;;
            r|P)
                        PERM=1
                        REC=1
                        ;;
            v)
                        PERM=1
                        REC=1
                        SELF=1
                        ;;
            z)
                        COMPRESS="zopfli -c"
                        ;;
            s)
                        ENCODE="(openssl base64 2>&-||base64)"
                        DECODE="base64 -d"
                        COMPRESS="gzip -cn9"
                        DECOMPRESS="zcat"
                        ;;
            Z)
                        COMPRESS="compress -c"
                        DECOMPRESS="uncompress"
                        ;;
            x)
                        COMPRESS="xz --x86 --lzma2=preset=9e -c"
                        DECOMPRESS="unxz"
                        ;;
            6)
                        BASE64='1'
                        DECODE="(openssl base64 -d 2>&-||base64 --decode)"
                        ENCODE="(openssl base64 2>&-||base64)"
                        ;;
            9)
                        BASE64=''
                        ENCODE="base91"
                        DECODE="base91 -d"
                        ;;
            a)
                        BASE64=''
                        ENCODE="ascii85 -n"
                        DECODE="ascii85 -dn"
                        ;;
            w)
                        WIDTH=$OPTARG
                        ;;
            f)
                        BASE64=''
                        AA='1'
                        ;;
            h)
                        usage
            esac
done
ORIGOPT="$@"
shift $((OPTIND - 1))
 
FILE="${1-}"
[ -z "$SELF" ] || FILE=$0
OUT="${2-}"
[ -n "$FILE" ] || usage
[ -r "$FILE" ] || quit "Can't read $FILE"
[ -f "$FILE" ] || quit "$FILE is not a regular file"
 
if [ "$PERM" ]; then
            if [ "$OSTYPE" = "linux-gnu" ]; then
                        PERM=$(stat -c '%a' "$FILE")
            else
                        PERM=$(stat -f '%A' "$FILE")
            fi
            EXTRA=";chmod $PERM \$F"
fi
 
if [ "$CLIP" -a ! "${CLIPEXEC-}" ]; then
            echo "Copying to clipboard..."
            if [ "$OSTYPE" = "linux-gnu" ]; then
                        CLIP="xclip"
            else
                        CLIP="pbcopy"
            fi
            CLIPEXEC=1 bash $0 $ORIGOPT | $CLIP
            echo "Done"
            exit 0
fi
 
if [ "$OPTC" ]; then
            zopfli=$(zopfli -c "$FILE"|wc -c)
            xz=$(xz --x86 --lzma2=preset=9e -c "$FILE"|wc -c)
            if [ "$zopfli" -lt "$xz" ]; then
                        COMPRESS="zopfli -c"
            else
                        COMPRESS="xz --x86 --lzma2=preset=9e -c"
                        DECOMPRESS="unxz"
            fi
fi
 
if [ "${OUT}" ]; then
            FBASE=$OUT
elif [ "$REC" ]; then
            FBASE=$(realpath -s -- "$FILE" 2>&- || readlink -f -- "$FILE")
else
            FBASE=${FILE##*/}
fi
 
# escape metacharacters
OUT=$(printf "F=%q" "$FBASE")
if [ "$BASE64" ]; then
            LINE="$DECODE<<E-O|$DECOMPRESS>\$F&&echo OK$EXTRA"
elif [ "$AA" ]; then
            echo "aa -p"
            if [ "$PERM" ]; then
                        aa pasta "$FBASE" "$PERM" < "$FILE"
            else
                        aa pasta "$FBASE" < "$FILE"
            fi
            exit
else
            LINE="$DECODE<<'E-O'|$DECOMPRESS>\$F&&echo OK$EXTRA"
fi
if [ $(( ${#OUT} + ${#LINE} )) -lt "$WIDTH" ];
then
            echo "$OUT;$LINE"
else
            echo "$OUT"
            echo "$LINE"
fi
ENCODE="$ENCODE | tr -d '\n' | fold -w $WIDTH"
$COMPRESS "$FILE" | eval "$ENCODE"
echo
echo "E-O"
echo
