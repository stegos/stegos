#!/bin/bash
#
# Check if our commit is latest
# Create and update release body, with link of latest release.
#

set -x
tag=$TAG
title="Stegos nightly build"
commit_body="Commit: "
pipeline_build="Build: https://github.com/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
pattern=s/.*${commit_body}\(\[a-f0-9\]+\)\(\\s\|$\).*/\\1/p

our_commit=$(git rev-parse HEAD)

if [ -z "$our_commit" ]; then
  exit 1
fi

echo ${title} > release.md
echo "" >> release.md
echo ${commit_body}${our_commit} >> release.md
echo "" >> release.md
echo ${pipeline_build} >> release.md

release=$(hub release show ${tag})

if [ $? -eq 1 ]; then
  echo "No release for this tag was found, creating a new one"
  hub release create -p -F release.md ${tag}
fi

release_commit=$(echo ${release} | sed -En "${pattern}")

if [ -z "$release_commit" ]; then
  release_commit=$our_commit
fi


if git merge-base --is-ancestor ${release_commit} HEAD; then
  echo "Commit is from our history, overriding the artifact"
  if [ "${release_commit}" != "${our_commit}" ]; then
    echo "Updating commit message"
    hub release delete ${tag}
    hub release create -p -F release.md ${tag}
  fi
  cp $ASSET $TITLE
  hub release edit -a "$TITLE" -m ''  ${tag}
else
  echo "Looks like commit release commit ${release_commit} is from future, or from other conflicting branch."
  echo "Make sure to check this release, and re-run job if needed."
  exit 1
fi
