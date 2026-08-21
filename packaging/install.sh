#!/bin/sh
set -eu
if [ "$#" -lt 2 ]; then
  echo "usage: install.sh ARTIFACT INSTALL_ROOT [CONFIRMATION_TOKEN]" >&2
  exit 2
fi
artifact=$1
install_root=$2
if [ "$#" -lt 3 ]; then
  "$artifact" install --install-root "$install_root" --source-executable "$artifact"
  echo "Review the plan above, then rerun with its confirmation token." >&2
else
  "$artifact" install --install-root "$install_root" --source-executable "$artifact" --apply --confirm "$3"
fi
